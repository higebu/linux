// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Yuya Kusakabe (yuya.kusakabe@gmail.com)
 *
 * Helper for SRv6 Mobile (RFC 9433) selftests.
 *
 * Usage:
 *   srv6_mobile_send -m end-map -s <src> -d <dst> [--rh-type N]
 *                    [--segleft N] [--bad-srh] [--no-next-header]
 *                    [--no-rh] [--pre-rh0] [--segment ADDR]
 *                    [--l4 icmp|udp|tcp] [--l4-len N]
 *   srv6_mobile_send -m gtp6-d  -s <src> -d <dst> [-t TEID] [-q QFI]
 *                              [-P PDU_TYPE] [--echo] [--malformed]
 *   srv6_mobile_send -m gtp4-d  -s <src4> -d <dst4> [-t TEID] [-q QFI]
 *                              [-P PDU_TYPE] [--echo] [--malformed]
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
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
 * segment list then runs in 16-byte units.
 */
struct rh_fixed {
	struct ip6_rthdr rthdr;
	uint32_t type_data;
};

static_assert(sizeof(struct rh_fixed) == 8, "rh_fixed must be 8 bytes");

/* the largest packet built here: a Hop-by-Hop Options header, a
 * one-segment type 0 Routing Header, a two-segment SRH and a TCP header
 */
#define HBH_LEN		8
#define PAD_MAX		1400
#define END_MAP_PKT_MAX	(sizeof(struct ip6_hdr) + HBH_LEN + \
			 2 * sizeof(struct rh_fixed) + \
			 3 * sizeof(struct in6_addr) + sizeof(struct tcphdr))

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
	MODE_GTP4_D,
};

struct cfg {
	enum mode	mode;
	struct in6_addr	src6;
	struct in6_addr	dst6;
	struct in6_addr	segment;
	struct in_addr	src4;
	struct in_addr	dst4;
	uint32_t	teid;
	uint8_t		qfi;
	uint8_t		pdu_type;
	uint8_t		rh_type;
	uint8_t		segleft;
	uint8_t		l4;
	int		l4_len;
	bool		segment_set;
	bool		pdu_session_set;
	bool		echo;
	bool		malformed;
	bool		frag;
	bool		dup_pdu_session;
	bool		bad_srh;
	bool		no_next_header;
	bool		no_rh;
	bool		pre_rh0;
	bool		hbh_ra;
	bool		bad_csum;
	bool		zero_csum;
	bool		inner4;
	bool		active_srh;
	bool		gtp_len_set;
	uint16_t	gtp_len;
	uint8_t		tclass;
	uint8_t		inner_hlim;
	uint8_t		ext_len;
	bool		udp_csum;
	bool		rr;
	uint16_t	frag_off;
	uint16_t	pad;
};

static void usage(const char *bin)
{
	fprintf(stderr,
		"Usage: %s -m <mode> -s <src> -d <dst> [opts]\n"
		"\n"
		"Modes:\n"
		"  end-map    Send IPv6 + SRH + ICMPv6 echo for End.MAP testing\n"
		"  gtp6-d     Send IPv6 + UDP + GTPv1-U[+PDU Session] for End.M.GTP6.D testing\n"
		"  gtp4-d     Send IPv4 + UDP + GTPv1-U[+PDU Session] for H.M.GTP4.D testing\n"
		"\n"
		"Mode end-map options:\n"
		"  --rh-type <n>       Routing Header type (default 4, the SRH)\n"
		"  --segleft <n>       Routing Header Segments Left, 0 (default) or 1\n"
		"  --bad-srh           emit an SRH whose Last Entry exceeds its length (drop test)\n"
		"  --no-next-header    send a bare IPv6 header with Next Header 59\n"
		"  --no-rh             send no Routing Header\n"
		"  --pre-rh0           prepend a type 0 Routing Header with Segments Left 0\n"
		"  --segment <addr>    Routing Header segment (default: the destination)\n"
		"  --l4 <proto>        icmp (echo, default), udp or tcp (SYN)\n"
		"  --l4-len <n>        truncate the L4 header to n bytes\n"
		"  --hbh-ra            prepend a Hop-by-Hop Router Alert option\n"
		"\n"
		"Mode gtp6-d / gtp4-d options:\n"
		"  -t <teid>           GTP-U TEID (decimal or 0xHEX), default 0x123\n"
		"  -q <qfi>            QFI (requires --pdu-session)\n"
		"  -P <pdu-type>       PDU Type (requires --pdu-session)\n"
		"  --pdu-session       emit GTPv1-U long header + PDU Session extension\n"
		"  --echo              emit a GTPv1-U Echo Request instead of T-PDU\n"
		"  --malformed         emit an extension chain with ext_units=0 (drop test)\n"
		"  --dup-pdu-session   emit two PDU Session extension headers (drop test)\n"
		"  --frag              insert an IPv6 Fragment header (gtp6-d), or set\n"
		"                      More Fragments (gtp4-d) (drop test)\n"
		"  --frag-off <n>      IPv4 Fragment Offset in 8-byte units (gtp4-d)\n"
		"  --rr                add an IPv4 Record Route option (gtp4-d)\n"
		"  --udp-csum          send a UDP checksum (gtp4-d)\n"
		"  --pad <n>           append n zero bytes to the T-PDU (n <= 1400)\n"
		"  --bad-csum          send a wrong UDP checksum\n"
		"  --zero-csum         send a zero UDP checksum\n"
		"  --gtp-len <n>       GTP-U Length (default: what follows the header)\n"
		"  --ext-len <n>       PDU Session container length in 4-byte units (1..8)\n"
		"  --tclass <n>        outer Traffic Class or TOS\n"
		"  --inner-hlim <n>    T-PDU Hop Limit or TTL (default 64)\n"
		"  --inner4            send an IPv4 T-PDU\n"
		"  --active-srh        insert an SRH with Segments Left 1 (gtp6-d)\n"
		"\n"
		"Exit: 0 sent, 1 failure, 3 invalid arguments.\n",
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

static int parse_l4(const char *s, uint8_t *out)
{
	if (!strcmp(s, "icmp"))
		*out = IPPROTO_ICMPV6;
	else if (!strcmp(s, "udp"))
		*out = IPPROTO_UDP;
	else if (!strcmp(s, "tcp"))
		*out = IPPROTO_TCP;
	else
		return -1;
	return 0;
}

static enum mode parse_mode(const char *s)
{
	if (!strcmp(s, "end-map"))
		return MODE_END_MAP;
	if (!strcmp(s, "gtp6-d"))
		return MODE_GTP6_D;
	if (!strcmp(s, "gtp4-d"))
		return MODE_GTP4_D;
	return MODE_NONE;
}

static bool mode_is_v4_outer(enum mode m)
{
	return m == MODE_GTP4_D;
}

static int parse_args(int argc, char **argv, struct cfg *cfg)
{
	enum { OPT_PDU_SESSION = 256, OPT_ECHO, OPT_MALFORMED,
	       OPT_DUP_PDU_SESSION, OPT_FRAG, OPT_RH_TYPE, OPT_SEGLEFT,
	       OPT_BAD_SRH, OPT_NO_NEXT_HEADER, OPT_NO_RH, OPT_PRE_RH0,
	       OPT_SEGMENT, OPT_L4, OPT_L4_LEN };
	static const struct option longopts[] = {
		{ "pdu-session",     no_argument, NULL, OPT_PDU_SESSION },
		{ "echo",            no_argument, NULL, OPT_ECHO },
		{ "malformed",       no_argument, NULL, OPT_MALFORMED },
		{ "dup-pdu-session", no_argument, NULL, OPT_DUP_PDU_SESSION },
		{ "frag",            no_argument, NULL, OPT_FRAG },
		{ "rh-type",         required_argument, NULL, OPT_RH_TYPE },
		{ "segleft",         required_argument, NULL, OPT_SEGLEFT },
		{ "bad-srh",         no_argument, NULL, OPT_BAD_SRH },
		{ "no-next-header",  no_argument, NULL, OPT_NO_NEXT_HEADER },
		{ "no-rh",           no_argument, NULL, OPT_NO_RH },
		{ "pre-rh0",         no_argument, NULL, OPT_PRE_RH0 },
		{ "segment",         required_argument, NULL, OPT_SEGMENT },
		{ "l4",              required_argument, NULL, OPT_L4 },
		{ "l4-len",          required_argument, NULL, OPT_L4_LEN },
		{ "hbh-ra",          no_argument, NULL, 'H' },
		{ "bad-csum",        no_argument, NULL, 'b' },
		{ "zero-csum",       no_argument, NULL, 'z' },
		{ "gtp-len",         required_argument, NULL, 'g' },
		{ "ext-len",         required_argument, NULL, 'e' },
		{ "tclass",          required_argument, NULL, 'c' },
		{ "inner-hlim",      required_argument, NULL, 'l' },
		{ "inner4",          no_argument, NULL, '4' },
		{ "active-srh",      no_argument, NULL, 'a' },
		{ "udp-csum",        no_argument, NULL, 'u' },
		{ "rr",              no_argument, NULL, 'R' },
		{ "frag-off",        required_argument, NULL, 'o' },
		{ "pad",             required_argument, NULL, 'p' },
		{ NULL, 0, NULL, 0 },
	};
	uint32_t v;
	int c;

	cfg->teid = 0x123;
	cfg->rh_type = 4;	/* RFC 8754: the SRH is Routing Header type 4 */
	cfg->l4 = IPPROTO_ICMPV6;
	cfg->l4_len = -1;
	while ((c = getopt_long(argc, argv, "m:s:d:t:q:P:", longopts, NULL))
	       != -1) {
		switch (c) {
		case 'm':
			cfg->mode = parse_mode(optarg);
			break;
		case 's':
			if (mode_is_v4_outer(cfg->mode)) {
				if (inet_pton(AF_INET, optarg, &cfg->src4) != 1)
					return -1;
			} else {
				if (inet_pton(AF_INET6, optarg, &cfg->src6) != 1)
					return -1;
			}
			break;
		case 'd':
			if (mode_is_v4_outer(cfg->mode)) {
				if (inet_pton(AF_INET, optarg, &cfg->dst4) != 1)
					return -1;
			} else {
				if (inet_pton(AF_INET6, optarg, &cfg->dst6) != 1)
					return -1;
			}
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
		case OPT_DUP_PDU_SESSION:
			cfg->dup_pdu_session = true;
			break;
		case OPT_FRAG:
			cfg->frag = true;
			break;
		case OPT_RH_TYPE:
			if (parse_u8(optarg, &cfg->rh_type))
				return -1;
			break;
		case OPT_SEGLEFT:
			if (parse_u8(optarg, &cfg->segleft) || cfg->segleft > 1)
				return -1;
			break;
		case OPT_BAD_SRH:
			cfg->bad_srh = true;
			break;
		case OPT_NO_NEXT_HEADER:
			cfg->no_next_header = true;
			break;
		case OPT_NO_RH:
			cfg->no_rh = true;
			break;
		case OPT_PRE_RH0:
			cfg->pre_rh0 = true;
			break;
		case OPT_SEGMENT:
			if (inet_pton(AF_INET6, optarg, &cfg->segment) != 1)
				return -1;
			cfg->segment_set = true;
			break;
		case OPT_L4:
			if (parse_l4(optarg, &cfg->l4))
				return -1;
			break;
		case OPT_L4_LEN:
			if (parse_u32(optarg, &v) || v > sizeof(struct tcphdr))
				return -1;
			cfg->l4_len = v;
			break;
		case 'H':
			cfg->hbh_ra = true;
			break;
		case 'b':
			cfg->bad_csum = true;
			break;
		case 'z':
			cfg->zero_csum = true;
			break;
		case 'g':
			if (parse_u32(optarg, &v) || v > 0xffff)
				return -1;
			cfg->gtp_len = v;
			cfg->gtp_len_set = true;
			break;
		case 'e':
			if (parse_u8(optarg, &cfg->ext_len) || !cfg->ext_len ||
			    cfg->ext_len > 8)
				return -1;
			break;
		case 'c':
			if (parse_u8(optarg, &cfg->tclass))
				return -1;
			break;
		case 'l':
			if (parse_u8(optarg, &cfg->inner_hlim))
				return -1;
			break;
		case '4':
			cfg->inner4 = true;
			break;
		case 'a':
			cfg->active_srh = true;
			break;
		case 'u':
			cfg->udp_csum = true;
			break;
		case 'R':
			cfg->rr = true;
			break;
		case 'o':
			if (parse_u32(optarg, &v) || !v || v > 0x1fff)
				return -1;
			cfg->frag_off = v;
			break;
		case 'p':
			if (parse_u32(optarg, &v) || v > PAD_MAX)
				return -1;
			cfg->pad = v;
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
	const uint8_t *p = buf;
	uint16_t word;

	while (len > 1) {
		memcpy(&word, p, sizeof(word));
		sum += word;
		p += sizeof(word);
		len -= sizeof(word);
	}
	if (len)
		sum += *p;
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

/* Segment List[0] is @segment; with Segments Left > 0 the current
 * destination follows as Segment List[1], since the receiver rejects a
 * Segments Left that indexes past the list.
 */
static void put_rh(uint8_t *buf, size_t *off, uint8_t nexthdr,
		   uint8_t type, uint8_t segleft, bool bad_srh,
		   const struct in6_addr *segment, const struct in6_addr *dst)
{
	int nsegs = segleft ? 2 : 1;
	struct rh_fixed rh = {};

	rh.rthdr.ip6r_nxt = nexthdr;
	rh.rthdr.ip6r_len = 2 * nsegs;
	rh.rthdr.ip6r_type = type;
	rh.rthdr.ip6r_segleft = segleft;
	/* SRH Last Entry is the high byte of the type-specific word;
	 * --bad-srh claims one segment more than the header has room for,
	 * which seg6_validate_srh() rejects.
	 */
	rh.type_data = htonl((uint32_t)(nsegs - 1 + bad_srh) << 24);
	memcpy(buf + *off, &rh, sizeof(rh));
	*off += sizeof(rh);
	memcpy(buf + *off, segment, sizeof(*segment));
	*off += sizeof(*segment);
	if (nsegs > 1) {
		memcpy(buf + *off, dst, sizeof(*dst));
		*off += sizeof(*dst);
	}
}

/* returns the L4 header length; its checksum covers @final_dst */
static size_t put_l4(uint8_t *buf, uint8_t proto, const struct in6_addr *src,
		     const struct in6_addr *final_dst)
{
	struct icmp6_hdr icmp6 = {};
	struct udphdr udp = {};
	struct tcphdr tcp = {};

	switch (proto) {
	case IPPROTO_UDP:
		udp.uh_sport = htons(4242);
		udp.uh_dport = htons(4243);	/* closed: rt-3 answers */
		udp.uh_ulen = htons(sizeof(udp));
		udp.uh_sum = pseudo_csum(src, final_dst, sizeof(udp), proto,
					 &udp, sizeof(udp));
		if (!udp.uh_sum)
			udp.uh_sum = 0xffff;
		memcpy(buf, &udp, sizeof(udp));
		return sizeof(udp);
	case IPPROTO_TCP:
		tcp.th_sport = htons(4242);
		tcp.th_dport = htons(4243);	/* closed: rt-3 answers */
		tcp.th_seq = htonl(1);
		tcp.th_off = sizeof(tcp) / 4;
		tcp.th_flags = TH_SYN;
		tcp.th_win = htons(1024);
		tcp.th_sum = pseudo_csum(src, final_dst, sizeof(tcp), proto,
					 &tcp, sizeof(tcp));
		memcpy(buf, &tcp, sizeof(tcp));
		return sizeof(tcp);
	default:
		icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
		icmp6.icmp6_dataun.icmp6_un_data16[0] = htons(0x1234);
		icmp6.icmp6_dataun.icmp6_un_data16[1] = htons(1);
		icmp6.icmp6_cksum = pseudo_csum(src, final_dst, sizeof(icmp6),
						proto, &icmp6, sizeof(icmp6));
		memcpy(buf, &icmp6, sizeof(icmp6));
		return sizeof(icmp6);
	}
}

static int send_end_map(const struct cfg *cfg)
{
	struct sockaddr_in6 dst_addr = { .sin6_family = AF_INET6 };
	const struct in6_addr *segment, *final_dst;
	uint8_t buf[END_MAP_PKT_MAX] = {};
	struct ip6_hdr ip6 = {};
	size_t off, l4_len;
	uint8_t *nexthdr;
	ssize_t res;
	int fd;

	segment = cfg->segment_set ? &cfg->segment : &cfg->dst6;
	/* the receiver verifies L4 against the address it ends up with */
	final_dst = !cfg->no_rh && cfg->segleft ? segment : &cfg->dst6;

	ip6.ip6_flow = htonl(6u << 28);
	ip6.ip6_hops = 64;
	ip6.ip6_src = cfg->src6;
	ip6.ip6_dst = cfg->dst6;
	off = sizeof(ip6);
	nexthdr = &ip6.ip6_nxt;

	if (cfg->no_next_header) {
		*nexthdr = IPPROTO_NONE;
		goto send;
	}

	if (cfg->hbh_ra) {
		*nexthdr = IPPROTO_HOPOPTS;
		nexthdr = &buf[off];
		buf[off + 2] = 5;	/* Router Alert (RFC 2711), value 0 */
		buf[off + 3] = 2;
		buf[off + 6] = 1;	/* PadN */
		off += HBH_LEN;
	}

	if (cfg->pre_rh0) {

		*nexthdr = IPPROTO_ROUTING;
		nexthdr = &buf[off];
		put_rh(buf, &off, 0, 0, 0, false, &cfg->dst6, &cfg->dst6);
	}

	if (!cfg->no_rh) {
		*nexthdr = IPPROTO_ROUTING;
		nexthdr = &buf[off];
		put_rh(buf, &off, 0, cfg->rh_type, cfg->segleft, cfg->bad_srh,
		       segment, &cfg->dst6);
	}

	*nexthdr = cfg->l4;
	l4_len = put_l4(buf + off, cfg->l4, &cfg->src6, final_dst);
	if (cfg->l4_len >= 0 && (size_t)cfg->l4_len < l4_len)
		l4_len = cfg->l4_len;
	off += l4_len;

send:
	ip6.ip6_plen = htons(off - sizeof(ip6));
	memcpy(buf, &ip6, sizeof(ip6));

	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	dst_addr.sin6_addr = cfg->dst6;

	res = sendto(fd, buf, off, 0,
		     (struct sockaddr *)&dst_addr, sizeof(dst_addr));
	close(fd);
	if (res != (ssize_t)off) {
		perror("sendto");
		return 1;
	}
	return 0;
}

#define INNER_PAYLOAD_LEN	16
#define GPDU_MAX		(sizeof(struct gtp1_hdr_long) + 8 * 4 + \
				 sizeof(struct pdu_session_ext) + \
				 sizeof(struct ip6_hdr) + INNER_PAYLOAD_LEN + \
				 PAD_MAX)

/* write the T-PDU, an ICMPv6 echo, or an ICMP echo with --inner4, at
 * @buf and return its length; the --pad zero bytes add nothing to the
 * checksums but the length
 */
static size_t put_tpdu(uint8_t *buf, const struct cfg *cfg)
{
	uint8_t hlim = cfg->inner_hlim ? : 64;
	struct icmp6_hdr icmp6 = {};
	struct icmphdr icmp = {};
	struct ip6_hdr *ip6;
	struct iphdr *iph;

	if (cfg->inner4) {
		iph = (struct iphdr *)buf;
		iph->version = 4;
		iph->ihl = sizeof(*iph) >> 2;
		iph->tot_len = htons(sizeof(*iph) + sizeof(icmp) + cfg->pad);
		iph->ttl = hlim;
		iph->protocol = IPPROTO_ICMP;
		iph->saddr = htonl(0x0a640001);	/* 10.100.0.1 */
		iph->daddr = htonl(0x0a640002);	/* 10.100.0.2 */
		iph->check = csum_fold(csum_partial(iph, sizeof(*iph), 0));
		icmp.type = ICMP_ECHO;
		icmp.un.echo.id = htons(0xdead);
		icmp.un.echo.sequence = htons(1);
		icmp.checksum = csum_fold(csum_partial(&icmp, sizeof(icmp), 0));
		memcpy(iph + 1, &icmp, sizeof(icmp));
		return sizeof(*iph) + sizeof(icmp) + cfg->pad;
	}

	ip6 = (struct ip6_hdr *)buf;
	ip6->ip6_flow = htonl(6u << 28);
	ip6->ip6_plen = htons(sizeof(icmp6) + cfg->pad);
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hops = hlim;
	inet_pton(AF_INET6, "2001:db8:100::1", &ip6->ip6_src);
	inet_pton(AF_INET6, "2001:db8:100::2", &ip6->ip6_dst);
	icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6.icmp6_dataun.icmp6_un_data16[0] = htons(0xdead);
	icmp6.icmp6_dataun.icmp6_un_data16[1] = htons(1);
	icmp6.icmp6_cksum = pseudo_csum(&ip6->ip6_src, &ip6->ip6_dst,
					sizeof(icmp6) + cfg->pad,
					IPPROTO_ICMPV6, &icmp6, sizeof(icmp6));
	memcpy(ip6 + 1, &icmp6, sizeof(icmp6));
	return sizeof(*ip6) + sizeof(icmp6) + cfg->pad;
}

/* write the GTP-U header and, unless --echo, the T-PDU at @buf and return
 * their length
 */
static size_t put_gpdu(uint8_t *buf, const struct cfg *cfg)
{
	struct gtp1_hdr_long *gtphl = (struct gtp1_hdr_long *)buf;
	struct gtp1_hdr *gtph = &gtphl->base;
	size_t len = sizeof(*gtph);
	size_t ext;
	uint8_t *p;

	gtph->flags = GTP1U_FLAGS_BASE;
	gtph->type = cfg->echo ? GTP1U_ECHO_REQ : GTP1U_TPDU;
	gtph->tid = htonl(cfg->teid);

	if (cfg->pdu_session_set) {
		gtph->flags |= GTP1U_F_EXTHDR;
		gtphl->next = GTP1U_NH_PDU_SESSION;
		len = sizeof(*gtphl);

		/* --malformed claims a zero-length container */
		ext = cfg->ext_len ? : 1;
		p = buf + len;
		p[0] = cfg->malformed ? 0 : ext;
		p[1] = (cfg->pdu_type & 0xf) << 4;
		p[2] = cfg->qfi & 0x3f;
		p[ext * 4 - 1] = cfg->dup_pdu_session ? GTP1U_NH_PDU_SESSION
						      : 0;
		len += ext * 4;

		/* A T-PDU carries at most one PDU Session container; a
		 * second one chained after the first must be rejected.
		 */
		if (cfg->dup_pdu_session) {
			p = buf + len;
			p[0] = 1;
			p[1] = (cfg->pdu_type & 0xf) << 4;
			p[2] = cfg->qfi & 0x3f;
			len += sizeof(struct pdu_session_ext);
		}
	}

	if (!cfg->echo)
		len += put_tpdu(buf + len, cfg);
	gtph->length = htons(cfg->gtp_len_set ? cfg->gtp_len
					      : len - sizeof(*gtph));
	return len;
}

/* checksum the UDP datagram at @uh, then break or clear it if asked */
static void set_udp_csum(struct udphdr *uh, uint16_t sum,
			 const struct cfg *cfg)
{
	uh->check = sum ? : 0xffff;
	if (cfg->bad_csum)
		uh->check = uh->check == htons(1) ? htons(2) :
						    uh->check ^ htons(1);
	if (cfg->zero_csum)
		uh->check = 0;
}

static int send_gtp6_d(const struct cfg *cfg)
{
	uint8_t frame[sizeof(struct ip6_hdr) + sizeof(struct rh_fixed) +
		      2 * sizeof(struct in6_addr) + sizeof(struct ip6_frag) +
		      sizeof(struct udphdr) + GPDU_MAX];
	struct sockaddr_in6 dst_addr = { .sin6_family = AF_INET6 };
	size_t frame_len, off, udp_len;
	struct ip6_hdr *outer;
	struct udphdr *uh;
	uint8_t *nexthdr;
	ssize_t res;
	int fd;

	memset(frame, 0, sizeof(frame));
	outer = (struct ip6_hdr *)frame;
	outer->ip6_flow = htonl(6u << 28 | (uint32_t)cfg->tclass << 20);
	outer->ip6_hops = 64;
	outer->ip6_src = cfg->src6;
	outer->ip6_dst = cfg->dst6;
	nexthdr = &outer->ip6_nxt;
	off = sizeof(*outer);

	if (cfg->active_srh) {
		*nexthdr = IPPROTO_ROUTING;
		nexthdr = &frame[off];
		put_rh(frame, &off, 0, 4, 1, false, &cfg->dst6, &cfg->dst6);
	}

	if (cfg->frag) {
		struct ip6_frag *frag = (struct ip6_frag *)(frame + off);

		*nexthdr = IPPROTO_FRAGMENT;
		nexthdr = &frag->ip6f_nxt;
		/* offset 0 with the More Fragments flag set, so
		 * ipv6_skip_exthdr() reports a nonzero frag_off.
		 */
		frag->ip6f_offlg = htons(0x0001);
		frag->ip6f_ident = htonl(0xf00dface);
		off += sizeof(*frag);
	}

	*nexthdr = IPPROTO_UDP;
	uh = (struct udphdr *)(frame + off);
	frame_len = off + sizeof(*uh) + put_gpdu((uint8_t *)(uh + 1), cfg);
	udp_len = frame_len - off;
	outer->ip6_plen = htons(frame_len - sizeof(*outer));

	uh->source = htons(GTP1U_PORT);
	uh->dest = htons(GTP1U_PORT);
	uh->len = htons(udp_len);
	set_udp_csum(uh, pseudo_csum(&outer->ip6_src, &outer->ip6_dst, udp_len,
				     IPPROTO_UDP, uh, udp_len), cfg);

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

static int send_gtp4_d(const struct cfg *cfg)
{
	uint8_t frame[sizeof(struct iphdr) + 8 + sizeof(struct udphdr) +
		      GPDU_MAX];
	struct sockaddr_in dst_addr = { .sin_family = AF_INET };
	size_t frame_len, ihl, udp_len;
	struct iphdr *outer;
	struct udphdr *uh;
	uint32_t sum;
	ssize_t res;
	int fd, one = 1;

	memset(frame, 0, sizeof(frame));
	outer = (struct iphdr *)frame;
	ihl = sizeof(*outer);
	if (cfg->rr) {
		/* Record Route with one empty slot, then End of Options */
		frame[ihl] = IPOPT_RR;
		frame[ihl + 1] = 7;
		frame[ihl + 2] = 4;
		ihl += 8;
	}

	uh = (struct udphdr *)(frame + ihl);
	frame_len = ihl + sizeof(*uh) + put_gpdu((uint8_t *)(uh + 1), cfg);
	udp_len = frame_len - ihl;

	outer->version = 4;
	outer->ihl = ihl >> 2;
	outer->tos = cfg->tclass;
	outer->tot_len = htons(frame_len);
	outer->id = 0;
	if (cfg->frag)
		outer->frag_off = htons(IP_MF);
	else if (cfg->frag_off)
		outer->frag_off = htons(cfg->frag_off);
	else
		outer->frag_off = htons(IP_DF);
	outer->ttl = 64;
	outer->protocol = IPPROTO_UDP;
	outer->saddr = cfg->src4.s_addr;
	outer->daddr = cfg->dst4.s_addr;
	outer->check = 0;
	outer->check = csum_fold(csum_partial(outer, ihl, 0));

	uh->source = htons(GTP1U_PORT);
	uh->dest = htons(GTP1U_PORT);
	uh->len = htons(udp_len);
	/* optional for IPv4 outer, and zero unless asked for */
	uh->check = 0;
	if (cfg->udp_csum || cfg->bad_csum) {
		sum = csum_partial(&outer->saddr, 2 * sizeof(outer->saddr), 0);
		sum += htons(IPPROTO_UDP);
		sum += htons(udp_len);
		set_udp_csum(uh, csum_fold(csum_partial(uh, udp_len, sum)),
			     cfg);
	}

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	/* IPPROTO_RAW already implies IP_HDRINCL on Linux, but set it
	 * explicitly so the kernel does not regenerate the IP header.
	 */
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) {
		perror("IP_HDRINCL");
		close(fd);
		return 1;
	}
	dst_addr.sin_addr.s_addr = outer->daddr;

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
	case MODE_GTP4_D:
		return send_gtp4_d(&cfg);
	default:
		usage(argv[0]);
		return 3;
	}
}
