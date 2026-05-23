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
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
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

/* the largest packet built here: a one-segment type 0 Routing Header,
 * a two-segment SRH and a TCP header
 */
#define END_MAP_PKT_MAX	(sizeof(struct ip6_hdr) + \
			 2 * sizeof(struct rh_fixed) + \
			 3 * sizeof(struct in6_addr) + sizeof(struct tcphdr))

enum mode {
	MODE_NONE,
	MODE_END_MAP,
};

struct cfg {
	enum mode	mode;
	struct in6_addr	src6;
	struct in6_addr	dst6;
	struct in6_addr	segment;
	uint8_t		rh_type;
	uint8_t		segleft;
	uint8_t		l4;
	int		l4_len;
	bool		segment_set;
	bool		bad_srh;
	bool		no_next_header;
	bool		no_rh;
	bool		pre_rh0;
};

static void usage(const char *bin)
{
	fprintf(stderr,
		"Usage: %s -m <mode> -s <src> -d <dst> [opts]\n"
		"\n"
		"Modes:\n"
		"  end-map    Send IPv6 + SRH + ICMPv6 echo for End.MAP testing\n"
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
	return MODE_NONE;
}

static int parse_args(int argc, char **argv, struct cfg *cfg)
{
	enum { OPT_RH_TYPE = 256, OPT_SEGLEFT, OPT_BAD_SRH,
	       OPT_NO_NEXT_HEADER, OPT_NO_RH, OPT_PRE_RH0, OPT_SEGMENT,
	       OPT_L4, OPT_L4_LEN };
	static const struct option longopts[] = {
		{ "rh-type",         required_argument, NULL, OPT_RH_TYPE },
		{ "segleft",         required_argument, NULL, OPT_SEGLEFT },
		{ "bad-srh",         no_argument, NULL, OPT_BAD_SRH },
		{ "no-next-header",  no_argument, NULL, OPT_NO_NEXT_HEADER },
		{ "no-rh",           no_argument, NULL, OPT_NO_RH },
		{ "pre-rh0",         no_argument, NULL, OPT_PRE_RH0 },
		{ "segment",         required_argument, NULL, OPT_SEGMENT },
		{ "l4",              required_argument, NULL, OPT_L4 },
		{ "l4-len",          required_argument, NULL, OPT_L4_LEN },
		{ NULL, 0, NULL, 0 },
	};
	uint32_t v;
	int c;

	cfg->rh_type = 4;	/* RFC 8754: the SRH is Routing Header type 4 */
	cfg->l4 = IPPROTO_ICMPV6;
	cfg->l4_len = -1;
	while ((c = getopt_long(argc, argv, "m:s:d:", longopts, NULL))
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
	default:
		usage(argv[0]);
		return 3;
	}
}
