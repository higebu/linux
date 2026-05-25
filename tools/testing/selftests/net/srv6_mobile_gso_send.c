// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Yuya Kusakabe (yuya.kusakabe@gmail.com)
 *
 * GSO injector for the SRv6 Mobile (RFC 9433) selftests.
 *
 * Builds a single inner IPv6 / TCP segment carrying @nsegs * @seg bytes
 * and hands it to the stack as one TCP TSO super-frame via an AF_PACKET
 * socket with a virtio_net_hdr (the same mechanism tun/tap uses to inject
 * GSO frames).  The frame is injected on the sender leg and forwarded
 * through the behavior under test, so the behavior sees a GSO skb larger
 * than the path MTU.  The segmentation engine splits it back into @nsegs
 * MTU-sized packets under the behavior's rewritten outer header.
 *
 * With -c it checks the GTP-U packets the segments leave an E behavior
 * in instead: each must carry one segment with matching UDP and GTP-U
 * lengths, a correct TCP checksum and the payload bytes sent.
 *
 * With -U it sends @nsegs G-PDUs to <addr> in one UDP_SEGMENT send, so that
 * a D behavior gets them as one UDP GSO skb.  Each carries a UDP datagram
 * of @seg bytes from <src6> to <dst6>.
 *
 * Usage: srv6_mobile_gso_send -i <iface> -D <dmac> -s <src6> -d <dst6>
 *                             -S <seg> -n <nsegs>
 *        srv6_mobile_gso_send -c -i <iface> -S <seg> -n <nsegs>
 *                             [-T <timeout-ms>] [-r <path>]
 *        srv6_mobile_gso_send -U -A <addr> -s <src6> -d <dst6>
 *                             -S <seg> -n <nsegs>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/virtio_net.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define GTP1U_PORT	2152

#ifndef UDP_SEGMENT
#define UDP_SEGMENT	103
#endif

struct cfg {
	const char	*iface;
	uint8_t		dmac[ETH_ALEN];
	struct in6_addr	src6;
	struct in6_addr	dst6;
	int		seg;
	int		nsegs;
	bool		check;
	bool		udp_gso;
	struct sockaddr_storage	addr;
	int		timeout_ms;
	const char	*ready_path;
};

static void usage(const char *bin)
{
	fprintf(stderr,
"Usage: %s -i <iface> -D <dmac> -s <src6> -d <dst6> -S <seg> -n <nsegs>\n"
"       %s -c -i <iface> -S <seg> -n <nsegs> [-T <timeout-ms>] [-r <path>]\n"
"       %s -U -A <addr> -s <src6> -d <dst6> -S <seg> -n <nsegs>\n"
"\n"
"  -i <iface>   interface to inject the TSO frame on\n"
"  -D <dmac>    next-hop destination MAC (aa:bb:cc:dd:ee:ff)\n"
"  -s <src6>    inner IPv6 source address\n"
"  -d <dst6>    inner IPv6 destination address\n"
"  -S <seg>     TCP segment size (becomes gso_size)\n"
"  -n <nsegs>   number of segments to coalesce into one GSO frame\n"
"  -c           check the GTP-U packets on <iface> instead of sending\n"
"  -T <ms>      check: wait window (default 2000)\n"
"  -r <path>    check: write \"ready\" to <path> once bound\n"
"  -U           send @nsegs G-PDUs to <addr> as one UDP GSO packet\n"
"  -A <addr>    -U: IPv4 or IPv6 GTP-U destination\n"
"\n"
"Exit: 0 sent / all segments intact, 1 failure, 3 usage error.\n",
		bin, bin, bin);
}

static int parse_mac(const char *s, uint8_t *mac)
{
	return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		      &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6
	       ? 0 : -1;
}

static uint32_t csum_partial(const void *buf, int len, uint32_t sum)
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

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static int parse_addr(const char *s, struct sockaddr_storage *ss)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

	if (inet_pton(AF_INET, s, &sin->sin_addr) == 1) {
		sin->sin_family = AF_INET;
		sin->sin_port = htons(GTP1U_PORT);
		return 0;
	}
	if (inet_pton(AF_INET6, s, &sin6->sin6_addr) == 1) {
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(GTP1U_PORT);
		return 0;
	}
	return -1;
}

static int parse_args(int argc, char **argv, struct cfg *cfg)
{
	int c;

	cfg->timeout_ms = 2000;
	while ((c = getopt(argc, argv, "ci:D:s:d:S:n:T:r:UA:")) != -1) {
		switch (c) {
		case 'U':
			cfg->udp_gso = true;
			break;
		case 'A':
			if (parse_addr(optarg, &cfg->addr))
				return -1;
			break;
		case 'c':
			cfg->check = true;
			break;
		case 'T':
			cfg->timeout_ms = atoi(optarg);
			break;
		case 'r':
			cfg->ready_path = optarg;
			break;
		case 'i':
			cfg->iface = optarg;
			break;
		case 'D':
			if (parse_mac(optarg, cfg->dmac))
				return -1;
			break;
		case 's':
			if (inet_pton(AF_INET6, optarg, &cfg->src6) != 1)
				return -1;
			break;
		case 'd':
			if (inet_pton(AF_INET6, optarg, &cfg->dst6) != 1)
				return -1;
			break;
		case 'S':
			cfg->seg = atoi(optarg);
			break;
		case 'n':
			cfg->nsegs = atoi(optarg);
			break;
		default:
			return -1;
		}
	}
	if ((!cfg->iface && !cfg->udp_gso) || cfg->seg <= 0 || cfg->nsegs <= 0)
		return -1;
	return 0;
}

/* return true if @buf is a GTP-U packet; @good tells whether it carries
 * one intact segment of the super-frame
 */
static bool check_gtpu(const uint8_t *buf, size_t len, const struct cfg *cfg,
		       bool *good)
{
	const struct ipv6hdr *ip6;
	const struct tcphdr *th;
	const uint8_t *gtp, *data;
	size_t off, ulen, hlen;
	uint32_t sum, seq;
	uint8_t next;
	int i, plen;

	*good = false;
	if (len < 1)
		return false;
	if (buf[0] >> 4 == 4) {
		off = (buf[0] & 0xf) * 4;
		if (len < off + 8 || buf[9] != IPPROTO_UDP)
			return false;
		if (ntohs(*(uint16_t *)(buf + 2)) != len)
			return true;
	} else if (buf[0] >> 4 == 6) {
		off = sizeof(*ip6);
		if (len < off + 8 || buf[6] != IPPROTO_UDP)
			return false;
		if (ntohs(*(uint16_t *)(buf + 4)) + off != len)
			return true;
	} else {
		return false;
	}
	if (ntohs(*(uint16_t *)(buf + off + 2)) != GTP1U_PORT)
		return false;

	ulen = ntohs(*(uint16_t *)(buf + off + 4));
	gtp = buf + off + 8;
	if (ulen != len - off || ulen < 16 ||
	    (gtp[0] & 0xf0) != 0x30 || gtp[1] != 0xff ||
	    ntohs(*(uint16_t *)(gtp + 2)) != ulen - 16)
		return true;

	hlen = 8;
	if (gtp[0] & 0x07)
		hlen = 12;
	next = gtp[0] & 0x04 ? gtp[11] : 0;
	while (next) {
		if (ulen < 8 + hlen + 4 || !gtp[hlen])
			return true;
		next = gtp[hlen + gtp[hlen] * 4 - 1];
		hlen += gtp[hlen] * 4;
	}

	ip6 = (const struct ipv6hdr *)(gtp + hlen);
	th = (const struct tcphdr *)(ip6 + 1);
	plen = ulen - 8 - hlen - sizeof(*ip6);
	if (plen < (int)sizeof(*th) || ip6->version != 6 ||
	    ip6->nexthdr != IPPROTO_TCP || ntohs(ip6->payload_len) != plen ||
	    plen - th->doff * 4 != cfg->seg)
		return true;

	sum = csum_partial(&ip6->saddr, sizeof(ip6->saddr), 0);
	sum = csum_partial(&ip6->daddr, sizeof(ip6->daddr), sum);
	sum += htons(plen);
	sum += htons(IPPROTO_TCP);
	if (csum_fold(csum_partial(th, plen, sum)))
		return true;

	/* the injected payload byte i is (uint8_t)i, and seq 1 is byte 0 */
	seq = ntohl(th->seq) - 1;
	data = (const uint8_t *)th + th->doff * 4;
	for (i = 0; i < cfg->seg; i++)
		if (data[i] != (uint8_t)(seq + i))
			return true;

	*good = true;
	return true;
}

static int elapsed_ms(const struct timespec *t0)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - t0->tv_sec) * 1000 +
	       (now.tv_nsec - t0->tv_nsec) / 1000000;
}

static int check(const struct cfg *cfg)
{
	struct pollfd pfd = { .events = POLLIN };
	int good = 0, bad = 0, remaining;
	struct timespec t0;
	uint8_t buf[2048];
	bool ok;
	ssize_t n;

	pfd.fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (pfd.fd < 0) {
		perror("socket(AF_PACKET)");
		return 3;
	}
	if (setsockopt(pfd.fd, SOL_SOCKET, SO_BINDTODEVICE, cfg->iface,
		       strlen(cfg->iface))) {
		perror("SO_BINDTODEVICE");
		close(pfd.fd);
		return 3;
	}
	if (cfg->ready_path) {
		FILE *fp = fopen(cfg->ready_path, "w");

		if (!fp || fputs("ready\n", fp) == EOF || fclose(fp)) {
			perror("ready file");
			close(pfd.fd);
			return 3;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (good + bad < cfg->nsegs) {
		remaining = cfg->timeout_ms - elapsed_ms(&t0);
		if (remaining <= 0 || poll(&pfd, 1, remaining) <= 0)
			break;
		n = recv(pfd.fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n < 0)
			continue;
		if (check_gtpu(buf, n, cfg, &ok)) {
			if (ok)
				good++;
			else
				bad++;
		}
	}
	close(pfd.fd);
	fprintf(stderr, "%d intact, %d damaged GTP-U packets\n", good, bad);
	return good == cfg->nsegs && !bad ? 0 : 1;
}

/* each G-PDU is a short GTP-U header and an IPv6/UDP datagram whose
 * payload bytes start at the G-PDU index
 */
static int send_udp_gso(const struct cfg *cfg)
{
	int gpdu = 8 + sizeof(struct ipv6hdr) + 8 + cfg->seg;
	uint8_t *buf, *p, *data;
	struct ipv6hdr *ip6;
	uint16_t *uh;
	uint32_t sum;
	int fd, i, k;
	ssize_t n;

	buf = calloc(cfg->nsegs, gpdu);
	if (!buf) {
		perror("calloc");
		return 1;
	}
	for (k = 0; k < cfg->nsegs; k++) {
		p = buf + k * gpdu;
		p[0] = 0x30;		/* GTPv1-U, short header */
		p[1] = 0xff;		/* T-PDU */
		*(uint16_t *)(p + 2) = htons(gpdu - 8);
		*(uint32_t *)(p + 4) = htonl(0x123);

		ip6 = (struct ipv6hdr *)(p + 8);
		ip6->version = 6;
		ip6->payload_len = htons(8 + cfg->seg);
		ip6->nexthdr = IPPROTO_UDP;
		ip6->hop_limit = 64;
		ip6->saddr = cfg->src6;
		ip6->daddr = cfg->dst6;

		uh = (uint16_t *)(ip6 + 1);
		uh[0] = htons(4242);
		uh[1] = htons(9);	/* closed: the receiver answers */
		uh[2] = htons(8 + cfg->seg);
		data = (uint8_t *)(uh + 4);
		for (i = 0; i < cfg->seg; i++)
			data[i] = (uint8_t)(k + i);

		sum = csum_partial(&ip6->saddr, sizeof(ip6->saddr), 0);
		sum = csum_partial(&ip6->daddr, sizeof(ip6->daddr), sum);
		sum += htons(8 + cfg->seg);
		sum += htons(IPPROTO_UDP);
		uh[3] = csum_fold(csum_partial(uh, 8 + cfg->seg, sum));
		if (!uh[3])
			uh[3] = 0xffff;
	}

	fd = socket(cfg->addr.ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		free(buf);
		return 1;
	}
	if (setsockopt(fd, IPPROTO_UDP, UDP_SEGMENT, &gpdu, sizeof(gpdu))) {
		perror("UDP_SEGMENT");
		close(fd);
		free(buf);
		return 1;
	}
	n = sendto(fd, buf, cfg->nsegs * gpdu, 0, (struct sockaddr *)&cfg->addr,
		   sizeof(cfg->addr));
	close(fd);
	free(buf);
	if (n != cfg->nsegs * gpdu) {
		perror("sendto");
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct cfg cfg = {};
	struct sockaddr_ll sll = { .sll_family = AF_PACKET };
	struct virtio_net_hdr *vh;
	struct ipv6hdr *ip6;
	struct tcphdr *th;
	uint8_t *buf, *eth, *data;
	int payload, frame_len, fd, i;
	uint32_t sum;
	ssize_t n;

	if (parse_args(argc, argv, &cfg)) {
		usage(argv[0]);
		return 3;
	}
	if (cfg.check)
		return check(&cfg);
	if (cfg.udp_gso)
		return send_udp_gso(&cfg);

	payload = cfg.seg * cfg.nsegs;
	frame_len = sizeof(*vh) + ETH_HLEN + sizeof(*ip6) + sizeof(*th) +
		    payload;
	buf = calloc(1, frame_len);
	if (!buf) {
		perror("calloc");
		return 1;
	}

	vh = (struct virtio_net_hdr *)buf;
	eth = buf + sizeof(*vh);
	ip6 = (struct ipv6hdr *)(eth + ETH_HLEN);
	th = (struct tcphdr *)(ip6 + 1);
	data = (uint8_t *)(th + 1);
	for (i = 0; i < payload; i++)
		data[i] = (uint8_t)i;

	memcpy(eth, cfg.dmac, ETH_ALEN);
	eth[ETH_ALEN] = 0x02;
	eth[2 * ETH_ALEN - 1] = 0x01;
	*(uint16_t *)(eth + 2 * ETH_ALEN) = htons(ETH_P_IPV6);

	ip6->version = 6;
	ip6->payload_len = htons(sizeof(*th) + payload);
	ip6->nexthdr = IPPROTO_TCP;
	ip6->hop_limit = 64;
	ip6->saddr = cfg.src6;
	ip6->daddr = cfg.dst6;

	th->source = htons(12345);
	th->dest = htons(80);
	th->seq = htonl(1);
	th->doff = sizeof(*th) / 4;
	th->psh = 1;
	th->ack = 1;
	th->window = htons(65535);
	/* CHECKSUM_PARTIAL: the checksum field carries the folded
	 * pseudo-header sum over the whole TCP length, which the
	 * segmentation engine adjusts to each segment.
	 */
	sum = csum_partial(&ip6->saddr, sizeof(ip6->saddr), 0);
	sum = csum_partial(&ip6->daddr, sizeof(ip6->daddr), sum);
	sum += htons(sizeof(*th) + payload);
	sum += htons(IPPROTO_TCP);
	th->check = ~csum_fold(sum);

	vh->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	vh->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
	vh->gso_size = cfg.seg;
	vh->hdr_len = ETH_HLEN + sizeof(*ip6) + sizeof(*th);
	vh->csum_start = ETH_HLEN + sizeof(*ip6);
	vh->csum_offset = offsetof(struct tcphdr, check);

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
	if (fd < 0) {
		perror("socket(AF_PACKET)");
		free(buf);
		return 1;
	}

	i = 1;
	if (setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR, &i, sizeof(i))) {
		perror("PACKET_VNET_HDR");
		close(fd);
		free(buf);
		return 1;
	}

	sll.sll_ifindex = if_nametoindex(cfg.iface);
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, cfg.dmac, ETH_ALEN);

	n = sendto(fd, buf, frame_len, 0, (struct sockaddr *)&sll, sizeof(sll));
	close(fd);
	free(buf);
	if (n != frame_len) {
		perror("sendto");
		return 1;
	}
	return 0;
}
