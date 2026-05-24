// SPDX-License-Identifier: GPL-2.0
/*
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
 * Usage: srv6_mobile_gso_send -i <iface> -D <dmac> -s <src6> -d <dst6>
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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct cfg {
	const char	*iface;
	uint8_t		dmac[ETH_ALEN];
	struct in6_addr	src6;
	struct in6_addr	dst6;
	int		seg;
	int		nsegs;
};

static void usage(const char *bin)
{
	fprintf(stderr,
"Usage: %s -i <iface> -D <dmac> -s <src6> -d <dst6> -S <seg> -n <nsegs>\n"
"\n"
"  -i <iface>   interface to inject the TSO frame on\n"
"  -D <dmac>    next-hop destination MAC (aa:bb:cc:dd:ee:ff)\n"
"  -s <src6>    inner IPv6 source address\n"
"  -d <dst6>    inner IPv6 destination address\n"
"  -S <seg>     TCP segment size (becomes gso_size)\n"
"  -n <nsegs>   number of segments to coalesce into one GSO frame\n"
"\n"
"Exit: 0 sent, 1 failure, 3 usage error.\n",
		bin);
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

static int parse_args(int argc, char **argv, struct cfg *cfg)
{
	int c;

	while ((c = getopt(argc, argv, "i:D:s:d:S:n:")) != -1) {
		switch (c) {
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
	if (!cfg->iface || cfg->seg <= 0 || cfg->nsegs <= 0)
		return -1;
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
	/* CHECKSUM_PARTIAL: the checksum field carries the pseudo-header sum
	 * (without length); the segmentation engine completes it per segment.
	 */
	sum = csum_partial(&ip6->saddr, sizeof(ip6->saddr), 0);
	sum = csum_partial(&ip6->daddr, sizeof(ip6->daddr), sum);
	sum += htonl(IPPROTO_TCP);
	th->check = csum_fold(sum);

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
