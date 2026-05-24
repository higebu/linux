// SPDX-License-Identifier: GPL-2.0
/*
 * Subsystem-wide AF_PACKET receiver for SRv6 Mobile (RFC 9433)
 * selftests.  Captures the encapsulated packet emitted by an SRv6
 * Mobile behavior on the egress interface, parses the outer chain
 * (and PDU Session extension header where applicable), and compares
 * each field against the caller-supplied expected value.
 *
 * Supported modes:
 *
 *   gtp4-e   -- expect IPv4 / UDP / GTPv1-U [/ PDU Session ext] /
 *               inner T-PDU emitted by End.M.GTP4.E
 *               (RFC 9433 Section 6.6).
 *
 * Exit codes:
 *   0  matched
 *   1  mismatch (no packet within the wait window matched all fields)
 *   2  timeout (no packet received within the wait window)
 *   3  usage / setup error
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define GTP1U_PORT		2152

#define GTP1U_FLAGS_BASE	0x30
#define GTP1U_F_EXTHDR		0x04
#define GTP1U_TPDU		0xff
#define GTP1U_NH_PDU_SESSION	0x85

struct gtp1_hdr {
	uint8_t  flags;
	uint8_t  type;
	uint16_t length;
	uint32_t tid;
} __attribute__((packed));

struct gtp1_hdr_long {
	struct gtp1_hdr	base;
	uint16_t	seq;
	uint8_t		npdu;
	uint8_t		next;
} __attribute__((packed));

struct pdu_session_ext {
	uint8_t ext_len;
	uint8_t pdu_type_spare;
	uint8_t spare_qfi;
	uint8_t next_ext;
} __attribute__((packed));

enum mode {
	MODE_NONE,
	MODE_GTP4_E,
};

struct cfg {
	const char	*iface;
	enum mode	mode;
	struct in_addr	src4;
	struct in_addr	dst4;
	uint32_t	teid;
	uint8_t		qfi;
	uint8_t		pdu_type;
	bool		pdu_session_set;
	int		timeout_ms;
};

static void usage(const char *bin)
{
	fprintf(stderr,
"Usage: %s -i <iface> -m <mode> -s <src> -d <dst> [opts]\n"
"\n"
"Modes:\n"
"  gtp4-e      End.M.GTP4.E (IPv4/UDP/GTPv1-U[/PDU Session]/inner)\n"
"\n"
"Common options:\n"
"  -i <iface>          interface to bind AF_PACKET to\n"
"  -m <mode>           expected wire format mode\n"
"  -s <src>            expected outer source address\n"
"  -d <dst>            expected outer destination address\n"
"  -T <timeout-ms>     receive wait window (default 1500)\n"
"\n"
"Mode gtp4-e options:\n"
"  -t <teid>           expected GTP-U TEID (decimal or 0xHEX)\n"
"  -q <qfi>            expected QFI (when --pdu-session)\n"
"  -P <pdu-type>       expected PDU Type (when --pdu-session)\n"
"  --pdu-session       expect GTPv1-U long header + PDU Session ext\n"
"\n"
"Exit: 0 match, 1 mismatch, 2 timeout, 3 usage error.\n",
	bin);
}

static int parse_u32(const char *s, uint32_t *out)
{
	unsigned long v;
	char *end;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || !*s || *end || v > 0xffffffffUL)
		return -1;
	*out = (uint32_t)v;
	return 0;
}

static int parse_u8(const char *s, uint8_t *out)
{
	uint32_t v;

	if (parse_u32(s, &v) || v > 0xff)
		return -1;
	*out = (uint8_t)v;
	return 0;
}

static enum mode parse_mode(const char *s)
{
	if (!strcmp(s, "gtp4-e"))
		return MODE_GTP4_E;
	return MODE_NONE;
}

static int parse_args(int argc, char **argv, struct cfg *cfg)
{
	enum { OPT_PDU_SESSION = 256 };
	static const struct option longopts[] = {
		{ "pdu-session", no_argument, NULL, OPT_PDU_SESSION },
		{ NULL, 0, NULL, 0 },
	};
	int c;

	cfg->timeout_ms = 1500;
	while ((c = getopt_long(argc, argv, "i:m:s:d:T:t:q:P:",
				longopts, NULL)) != -1) {
		switch (c) {
		case 'i':
			cfg->iface = optarg;
			break;
		case 'm':
			cfg->mode = parse_mode(optarg);
			break;
		case 's':
			if (inet_pton(AF_INET, optarg, &cfg->src4) != 1)
				return -1;
			break;
		case 'd':
			if (inet_pton(AF_INET, optarg, &cfg->dst4) != 1)
				return -1;
			break;
		case 'T':
			if (parse_u32(optarg, (uint32_t *)&cfg->timeout_ms))
				return -1;
			break;
		case 't':
			if (parse_u32(optarg, &cfg->teid))
				return -1;
			break;
		case 'q':
			if (parse_u8(optarg, &cfg->qfi))
				return -1;
			break;
		case 'P':
			if (parse_u8(optarg, &cfg->pdu_type))
				return -1;
			break;
		case OPT_PDU_SESSION:
			cfg->pdu_session_set = true;
			break;
		default:
			return -1;
		}
	}
	if (!cfg->iface || cfg->mode == MODE_NONE)
		return -1;
	return 0;
}

static bool match_gtp4_e(const uint8_t *buf, size_t len, const struct cfg *cfg)
{
	const struct pdu_session_ext *ps;
	const struct gtp1_hdr_long *gtphl;
	const struct gtp1_hdr *gtph;
	const struct udphdr *uh;
	const struct iphdr *iph;
	size_t off = 0;
	uint8_t flags_exp;
	size_t gtp_hsz;

	if (len < sizeof(*iph))
		return false;
	iph = (const void *)(buf + off);
	if (iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return false;
	if (iph->saddr != cfg->src4.s_addr || iph->daddr != cfg->dst4.s_addr)
		return false;
	off += iph->ihl * 4;

	if (len < off + sizeof(*uh))
		return false;
	uh = (const void *)(buf + off);
	if (ntohs(uh->dest) != GTP1U_PORT || ntohs(uh->source) != GTP1U_PORT)
		return false;
	off += sizeof(*uh);

	flags_exp = cfg->pdu_session_set ? (GTP1U_FLAGS_BASE | GTP1U_F_EXTHDR)
					 : GTP1U_FLAGS_BASE;
	gtp_hsz = cfg->pdu_session_set ? sizeof(*gtphl) : sizeof(*gtph);
	if (len < off + gtp_hsz)
		return false;
	gtph = (const void *)(buf + off);
	if (gtph->flags != flags_exp || gtph->type != GTP1U_TPDU)
		return false;
	if (ntohl(gtph->tid) != cfg->teid)
		return false;
	if (cfg->pdu_session_set) {
		gtphl = (const void *)(buf + off);
		if (gtphl->next != GTP1U_NH_PDU_SESSION)
			return false;
	}
	off += gtp_hsz;

	if (!cfg->pdu_session_set)
		return true;

	if (len < off + sizeof(*ps))
		return false;
	ps = (const void *)(buf + off);
	if (ps->ext_len != 1)
		return false;
	if (((ps->pdu_type_spare >> 4) & 0xf) != cfg->pdu_type)
		return false;
	if ((ps->spare_qfi & 0x3f) != cfg->qfi)
		return false;
	return true;
}

static int elapsed_ms(const struct timespec *t0)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - t0->tv_sec) * 1000 +
	       (now.tv_nsec - t0->tv_nsec) / 1000000;
}

int main(int argc, char **argv)
{
	struct timespec t0;
	struct cfg cfg = {};
	uint8_t buf[2048];
	struct pollfd pfd;
	bool seen = false;
	int fd, rc;

	if (parse_args(argc, argv, &cfg)) {
		usage(argv[0]);
		return 3;
	}

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (fd < 0) {
		perror("socket(AF_PACKET)");
		return 3;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
		       cfg.iface, strlen(cfg.iface))) {
		perror("SO_BINDTODEVICE");
		close(fd);
		return 3;
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		int remaining = cfg.timeout_ms - elapsed_ms(&t0);
		ssize_t n;

		if (remaining <= 0)
			break;

		rc = poll(&pfd, 1, remaining);
		if (rc == 0)
			break;
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			close(fd);
			return 3;
		}

		n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			perror("recv");
			close(fd);
			return 3;
		}

		seen = true;
		if (cfg.mode == MODE_GTP4_E &&
		    match_gtp4_e(buf, (size_t)n, &cfg)) {
			close(fd);
			return 0;
		}
	}

	close(fd);
	return seen ? 1 : 2;
}
