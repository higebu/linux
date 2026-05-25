// SPDX-License-Identifier: GPL-2.0
/*
 * Helper for SRv6 Mobile (RFC 9433) selftests.
 *
 * Usage:
 *   srv6_mobile_send -m end-map -s <src> -d <dst>
 *   srv6_mobile_send -m gtp6-d  -s <src> -d <dst> [-t TEID] [-q QFI]
 *                              [-P PDU_TYPE] [--echo] [--malformed]
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define GTP1U_PORT		2152

/* GTPv1-U mandatory header flags: Version=1 (bits 7..5 = 001) +
 * Protocol Type=1 (bit 4); E/S/PN are zero in the base.
 */
#define GTP1U_FLAGS_BASE	0x30
#define GTP1U_F_EXTHDR		0x04
#define GTP1U_TPDU		0xff
#define GTP1U_ECHO_REQ		0x01
#define GTP1U_NH_PDU_SESSION	0x85

/* RFC 8200 Routing header common fields are 4 bytes; an additional
 * 4 bytes of type-specific data follow (the Reserved field for the
 * deprecated type 0, or first_segment/flags/tag for SRH type 4).  The
 * segment list then runs in 16-byte units, giving a total of 24 bytes
 * for one segment -- which is what ip6r_len = 2 advertises.
 */
struct srh {
	struct ip6_rthdr rthdr;
	uint32_t type_data;
	struct in6_addr segments[1];
};

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
	MODE_END_MAP,
	MODE_GTP6_D,
};

struct cfg {
	enum mode	mode;
	struct in6_addr	src6;
	struct in6_addr	dst6;
	uint32_t	teid;
	uint8_t		qfi;
	uint8_t		pdu_type;
	bool		pdu_session_set;
	bool		echo;
	bool		malformed;
};

static void usage(const char *bin)
{
	fprintf(stderr,
"Usage: %s -m <mode> -s <src> -d <dst> [opts]\n"
"\n"
"Modes:\n"
"  end-map    Send IPv6 + SRH + ICMPv6 echo for End.MAP testing\n"
"  gtp6-d     Send IPv6 + UDP + GTPv1-U[+PDU Session] for End.M.GTP6.D testing\n"
"\n"
"Mode gtp6-d options:\n"
"  -t <teid>           GTP-U TEID (decimal or 0xHEX), default 0x123\n"
"  -q <qfi>            QFI (requires --pdu-session)\n"
"  -P <pdu-type>       PDU Type (requires --pdu-session)\n"
"  --pdu-session       emit GTPv1-U long header + PDU Session extension\n"
"  --echo              emit a GTPv1-U Echo Request instead of T-PDU\n"
"  --malformed         emit an extension chain with ext_units=0 (drop test)\n"
"\n"
"Exit: 0 sent, 1 failure, 3 usage error.\n",
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
	if (!strcmp(s, "end-map"))
		return MODE_END_MAP;
	if (!strcmp(s, "gtp6-d"))
		return MODE_GTP6_D;
	return MODE_NONE;
}

static int parse_args(int argc, char **argv, struct cfg *cfg)
{
	enum { OPT_PDU_SESSION = 256, OPT_ECHO, OPT_MALFORMED };
	static const struct option longopts[] = {
		{ "pdu-session", no_argument, NULL, OPT_PDU_SESSION },
		{ "echo",        no_argument, NULL, OPT_ECHO },
		{ "malformed",   no_argument, NULL, OPT_MALFORMED },
		{ NULL, 0, NULL, 0 },
	};
	int c;

	cfg->teid = 0x123;
	while ((c = getopt_long(argc, argv, "m:s:d:t:q:P:", longopts, NULL))
	       != -1) {
		switch (c) {
		case 'm':
			cfg->mode = parse_mode(optarg);
			break;
		case 's':
			if (inet_pton(AF_INET6, optarg, &cfg->src6) != 1)
				return -1;
			break;
		case 'd':
			if (inet_pton(AF_INET6, optarg, &cfg->dst6) != 1)
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
		case OPT_ECHO:
			cfg->echo = true;
			break;
		case OPT_MALFORMED:
			cfg->malformed = true;
			break;
		default:
			return -1;
		}
	}
	if (cfg->mode == MODE_NONE)
		return -1;
	return 0;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static uint32_t csum_partial(const void *buf, size_t len, uint32_t sum)
{
	const uint16_t *p = buf;

	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8_t *)p;
	return sum;
}

static uint16_t pseudo_csum(const struct in6_addr *src,
			    const struct in6_addr *dst,
			    uint32_t plen, uint8_t nexthdr,
			    const void *payload, size_t len)
{
	uint32_t nh = htonl(nexthdr);
	uint32_t pl = htonl(plen);
	uint32_t sum;

	sum = csum_partial(src, sizeof(*src), 0);
	sum = csum_partial(dst, sizeof(*dst), sum);
	sum = csum_partial(&pl, sizeof(pl), sum);
	sum = csum_partial(&nh, sizeof(nh), sum);
	sum = csum_partial(payload, len, sum);
	return csum_fold(sum);
}

static int send_end_map(const struct cfg *cfg)
{
	uint8_t frame[sizeof(struct ip6_hdr) + sizeof(struct srh) +
		      sizeof(struct icmp6_hdr)];
	struct sockaddr_in6 dst_addr = { .sin6_family = AF_INET6 };
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *ip6;
	struct srh *srh;
	ssize_t res;
	int fd;

	memset(frame, 0, sizeof(frame));
	ip6 = (struct ip6_hdr *)frame;
	srh = (struct srh *)(frame + sizeof(*ip6));
	icmp6 = (struct icmp6_hdr *)(frame + sizeof(*ip6) + sizeof(*srh));

	ip6->ip6_flow = htonl(6u << 28);
	ip6->ip6_plen = htons(sizeof(*srh) + sizeof(*icmp6));
	ip6->ip6_nxt = IPPROTO_ROUTING;
	ip6->ip6_hops = 64;
	ip6->ip6_src = cfg->src6;
	ip6->ip6_dst = cfg->dst6;

	srh->rthdr.ip6r_nxt = IPPROTO_ICMPV6;
	srh->rthdr.ip6r_len = 2;		/* (1 + ip6r_len) * 8 = 24 */
	srh->rthdr.ip6r_type = 0;		/* RFC 8754: SRH is type 4 */
	srh->rthdr.ip6r_segleft = 0;
	srh->segments[0] = ip6->ip6_dst;

	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_dataun.icmp6_un_data16[0] = htons(0x1234);
	icmp6->icmp6_dataun.icmp6_un_data16[1] = htons(1);
	icmp6->icmp6_cksum = pseudo_csum(&ip6->ip6_src, &ip6->ip6_dst,
					 sizeof(*icmp6), IPPROTO_ICMPV6,
					 icmp6, sizeof(*icmp6));

	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	dst_addr.sin6_addr = ip6->ip6_dst;

	res = sendto(fd, frame, sizeof(frame), 0,
		     (struct sockaddr *)&dst_addr, sizeof(dst_addr));
	close(fd);
	if (res != (ssize_t)sizeof(frame)) {
		perror("sendto");
		return 1;
	}
	return 0;
}

#define INNER_PAYLOAD_LEN	16

static int send_gtp6_d(const struct cfg *cfg)
{
	uint8_t frame[sizeof(struct ip6_hdr) + sizeof(struct udphdr) +
		      sizeof(struct gtp1_hdr_long) +
		      sizeof(struct pdu_session_ext) +
		      sizeof(struct ip6_hdr) + INNER_PAYLOAD_LEN];
	struct sockaddr_in6 dst_addr = { .sin6_family = AF_INET6 };
	struct ip6_hdr *outer;
	struct udphdr *uh;
	uint8_t *gtp_buf;
	struct ip6_hdr *inner;
	struct icmp6_hdr inner_icmp = {};
	size_t gtp_hdr_len, payload_off, frame_len, plen;
	ssize_t res;
	int fd;

	memset(frame, 0, sizeof(frame));
	outer = (struct ip6_hdr *)frame;
	uh = (struct udphdr *)(frame + sizeof(*outer));
	gtp_buf = (uint8_t *)(uh + 1);

	if (cfg->pdu_session_set) {
		struct gtp1_hdr_long *gtphl = (struct gtp1_hdr_long *)gtp_buf;
		struct pdu_session_ext *ps;

		gtphl->base.flags = GTP1U_FLAGS_BASE | GTP1U_F_EXTHDR;
		gtphl->base.type = cfg->echo ? GTP1U_ECHO_REQ : GTP1U_TPDU;
		gtphl->base.tid = htonl(cfg->teid);
		gtphl->seq = 0;
		gtphl->npdu = 0;
		gtphl->next = GTP1U_NH_PDU_SESSION;

		ps = (struct pdu_session_ext *)(gtphl + 1);
		ps->ext_len = cfg->malformed ? 0 : 1;
		ps->pdu_type_spare = (cfg->pdu_type & 0xf) << 4;
		ps->spare_qfi = cfg->qfi & 0x3f;
		ps->next_ext = 0;

		gtp_hdr_len = sizeof(*gtphl) + sizeof(*ps);
	} else {
		struct gtp1_hdr *gtph = (struct gtp1_hdr *)gtp_buf;

		gtph->flags = GTP1U_FLAGS_BASE;
		gtph->type = cfg->echo ? GTP1U_ECHO_REQ : GTP1U_TPDU;
		gtph->tid = htonl(cfg->teid);
		gtp_hdr_len = sizeof(*gtph);
	}

	payload_off = sizeof(*outer) + sizeof(*uh) + gtp_hdr_len;

	if (cfg->echo) {
		/* GTP-U Echo carries no inner IP payload. */
		((struct gtp1_hdr *)gtp_buf)->length = htons(gtp_hdr_len -
							     sizeof(struct gtp1_hdr));
		frame_len = payload_off;
	} else {
		/* Inner IPv6 + ICMPv6 echo as the encapsulated T-PDU. */
		inner = (struct ip6_hdr *)(frame + payload_off);
		inner->ip6_flow = htonl(6u << 28);
		inner->ip6_plen = htons(sizeof(inner_icmp));
		inner->ip6_nxt = IPPROTO_ICMPV6;
		inner->ip6_hops = 64;
		if (inet_pton(AF_INET6, "2001:db8:100::1", &inner->ip6_src) != 1 ||
		    inet_pton(AF_INET6, "2001:db8:100::2", &inner->ip6_dst) != 1)
			return 1;

		inner_icmp.icmp6_type = ICMP6_ECHO_REQUEST;
		inner_icmp.icmp6_dataun.icmp6_un_data16[0] = htons(0xdead);
		inner_icmp.icmp6_dataun.icmp6_un_data16[1] = htons(1);
		inner_icmp.icmp6_cksum = pseudo_csum(&inner->ip6_src,
						     &inner->ip6_dst,
						     sizeof(inner_icmp),
						     IPPROTO_ICMPV6,
						     &inner_icmp,
						     sizeof(inner_icmp));

		memcpy(inner + 1, &inner_icmp, sizeof(inner_icmp));

		frame_len = payload_off + sizeof(*inner) + sizeof(inner_icmp);
		((struct gtp1_hdr *)gtp_buf)->length =
			htons(frame_len - payload_off + gtp_hdr_len -
			      sizeof(struct gtp1_hdr));
	}

	outer->ip6_flow = htonl(6u << 28);
	plen = frame_len - sizeof(*outer);
	outer->ip6_plen = htons(plen);
	outer->ip6_nxt = IPPROTO_UDP;
	outer->ip6_hops = 64;
	outer->ip6_src = cfg->src6;
	outer->ip6_dst = cfg->dst6;

	uh->source = htons(GTP1U_PORT);
	uh->dest = htons(GTP1U_PORT);
	uh->len = htons(plen);
	uh->check = 0;
	uh->check = pseudo_csum(&outer->ip6_src, &outer->ip6_dst, plen,
				IPPROTO_UDP, uh, plen);
	if (!uh->check)
		uh->check = 0xffff;

	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	dst_addr.sin6_addr = outer->ip6_dst;

	res = sendto(fd, frame, frame_len, 0,
		     (struct sockaddr *)&dst_addr, sizeof(dst_addr));
	close(fd);
	if (res != (ssize_t)frame_len) {
		perror("sendto");
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct cfg cfg = {};

	if (parse_args(argc, argv, &cfg)) {
		usage(argv[0]);
		return 3;
	}

	switch (cfg.mode) {
	case MODE_END_MAP:
		return send_end_map(&cfg);
	case MODE_GTP6_D:
		return send_gtp6_d(&cfg);
	default:
		usage(argv[0]);
		return 3;
	}
}
