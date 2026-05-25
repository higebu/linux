// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  SRv6 Mobile User Plane implementation
 *
 *  Author:
 *  Yuya Kusakabe <yuya.kusakabe@gmail.com>
 */

#include <linux/icmpv6.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/unaligned.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/gtp.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/ip_tunnels.h>
#include <net/ipv6.h>
#include <net/lwtunnel.h>
#include <net/route.h>
#include <net/seg6.h>
#ifdef CONFIG_IPV6_SEG6_HMAC
#include <net/seg6_hmac.h>
#endif
#include <uapi/linux/seg6_mobile.h>

#define SEG6_MOBILE_F_ATTR(i)		BIT(i)
#define SEG6_F_MOBILE_COUNTERS		SEG6_MOBILE_F_ATTR(SEG6_MOBILE_COUNTERS)

struct seg6_mobile_lwt;

struct seg6_mobile_action_desc {
	int action;
	unsigned long attrs;
	unsigned long optattrs;
	int (*input)(struct sk_buff *skb, struct seg6_mobile_lwt *slwt);

	/* Optional cross-attribute sanity check invoked from
	 * seg6_mobile_build_state() after all per-attribute parse()
	 * callbacks have populated @slwt.  Used by actions whose
	 * attribute constraints span more than one attribute (e.g.
	 * End.M.GTP4.E enforces v6_src_prefix_len + 32 <= 128).
	 */
	int (*validate)(struct seg6_mobile_lwt *slwt,
			struct netlink_ext_ack *extack);
};

struct seg6_mobile_action_param {
	int (*parse)(struct nlattr **attrs, struct seg6_mobile_lwt *slwt,
		     struct netlink_ext_ack *extack);
	int (*put)(struct sk_buff *skb, struct seg6_mobile_lwt *slwt);
	int (*cmp)(struct seg6_mobile_lwt *a, struct seg6_mobile_lwt *b);

	/* optional destroy() callback to release resources acquired in
	 * the corresponding parse() function.
	 */
	void (*destroy)(struct seg6_mobile_lwt *slwt);
};

struct pcpu_seg6_mobile_counters {
	u64_stats_t packets;
	u64_stats_t bytes;
	u64_stats_t errors;

	struct u64_stats_sync syncp;
};

/* User-space aggregate format for the per-CPU counters.  Kept private
 * to the kernel; userspace receives the values through SEG6_MOBILE_CNT_*
 * nested netlink attributes.
 */
struct seg6_mobile_counters {
	__u64 packets;
	__u64 bytes;
	__u64 errors;
};

#define seg6_mobile_alloc_pcpu_counters(__gfp)				\
	__netdev_alloc_pcpu_stats(struct pcpu_seg6_mobile_counters,	\
				  ((__gfp) | __GFP_ZERO))

struct seg6_mobile_lwt {
	int action;
	struct in6_addr nh6;
	struct in6_addr src_addr;
	u8 pdu_type;
	bool pdu_type_set;
	u8 v6_src_prefix_len;
	u8 sr_prefix_len;
	const struct seg6_mobile_action_desc *desc;
	struct pcpu_seg6_mobile_counters __percpu *pcpu_counters;

	/* required attrs are tracked by desc->attrs; optional attrs that
	 * the user actually configured are tracked here so that fill_encap
	 * / cmp / destroy can iterate only over what was parsed.
	 */
	unsigned long parsed_optattrs;
};

static struct seg6_mobile_lwt *seg6_mobile_lwtunnel(struct lwtunnel_state *lwt)
{
	return (struct seg6_mobile_lwt *)lwt->data;
}

enum seg6_mobile_srh_state {
	SEG6_MOBILE_SRH_ABSENT,
	SEG6_MOBILE_SRH_PRESENT,
	SEG6_MOBILE_SRH_MALFORMED,
};

/* Return the SRH if present and valid.  @state separates ABSENT from
 * MALFORMED so End.MAP can forward an SRH-less packet while still
 * dropping a malformed one.
 */
static struct ipv6_sr_hdr *
seg6_mobile_get_and_validate_srh(struct sk_buff *skb,
				 enum seg6_mobile_srh_state *state)
{
	struct ipv6_sr_hdr *srh;
	unsigned int srhoff = 0;
	int hdr_proto;
	int flags = 0;

	srh = seg6_get_srh(skb, 0);
	if (srh) {
#ifdef CONFIG_IPV6_SEG6_HMAC
		if (!seg6_hmac_validate_skb(skb)) {
			*state = SEG6_MOBILE_SRH_MALFORMED;
			return NULL;
		}
#endif
		*state = SEG6_MOBILE_SRH_PRESENT;
		return srh;
	}

	hdr_proto = ipv6_find_hdr(skb, &srhoff, IPPROTO_ROUTING, NULL, &flags);
	*state = hdr_proto == -ENOENT ? SEG6_MOBILE_SRH_ABSENT
				      : SEG6_MOBILE_SRH_MALFORMED;
	return NULL;
}

/* Length of the L4 header that must be made writable so its checksum
 * field can be patched when the IPv6 DA changes.  Returns 0 for L4
 * protocols whose checksum does not cover the IPv6 pseudo-header.
 */
static int seg6_mobile_l4_csum_hlen(u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
		return sizeof(struct tcphdr);
	case IPPROTO_UDP:
		return sizeof(struct udphdr);
	case IPPROTO_ICMPV6:
		return sizeof(struct icmp6hdr);
	}
	return 0;
}

/* Return a pointer to the L4 checksum field that needs the IPv6 DA
 * diff applied, or NULL if patching must be skipped.  Must be called
 * after the L4 header has been made writable.
 */
static __sum16 *seg6_mobile_l4_csum(struct sk_buff *skb, int l4_off,
				    u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
		return &((struct tcphdr *)(skb->data + l4_off))->check;
	case IPPROTO_UDP: {
		struct udphdr *uh = (struct udphdr *)(skb->data + l4_off);

		/* A zero UDPv6 checksum on a fully assembled skb signals
		 * "no checksum" (e.g. tunneled UDP); patching it would
		 * invent a spurious non-zero value.
		 */
		if (!uh->check && skb->ip_summed != CHECKSUM_PARTIAL)
			return NULL;
		return &uh->check;
	}
	case IPPROTO_ICMPV6:
		return &((struct icmp6hdr *)(skb->data + l4_off))->icmp6_cksum;
	}
	return NULL;
}

/* Rewrite the IPv6 destination address with @nh.  When @srh_present is
 * false the packet has no routing header, so the receiver delivers it
 * straight to the transport: walk any Hop-by-Hop / Destination Options /
 * Fragment chain to the L4 header and, when that transport uses the IPv6
 * pseudo-header, patch its checksum by the DA diff.  When a routing
 * header is present the receiver first advances the SID list (SRv6
 * restores DA to segments[0]) before delivering to L4, so the original
 * checksum stays valid and only skb->csum needs maintenance for
 * CHECKSUM_COMPLETE skbs.
 */
static int seg6_mobile_advance_da(struct sk_buff *skb,
				  const struct in6_addr *nh, bool srh_present)
{
	int l4_off = 0, l4_hlen = 0;
	struct in6_addr old_da;
	struct ipv6hdr *ip6h;
	__be16 frag_off;
	u8 nexthdr = 0;
	__sum16 *csum;
	int write_len;

	if (!pskb_may_pull(skb, sizeof(*ip6h)))
		return -EINVAL;

	ip6h = ipv6_hdr(skb);
	write_len = sizeof(*ip6h);

	if (!srh_present) {
		nexthdr = ip6h->nexthdr;
		l4_off = ipv6_skip_exthdr(skb, sizeof(*ip6h), &nexthdr,
					  &frag_off);
		if (l4_off < 0)
			return -EINVAL;

		/* Non-first fragments carry no L4 header at @l4_off (the
		 * Fragment header reports a non-zero offset); only the
		 * first fragment, which holds the transport header, is
		 * patched.
		 */
		if (frag_off == 0)
			l4_hlen = seg6_mobile_l4_csum_hlen(nexthdr);
		if (l4_hlen)
			write_len = l4_off + l4_hlen;
	}

	if (skb_ensure_writable(skb, write_len))
		return -ENOMEM;

	/* skb_ensure_writable() may change skb pointers; evaluate ip6h again */
	ip6h = ipv6_hdr(skb);
	old_da = ip6h->daddr;

	csum = l4_hlen ? seg6_mobile_l4_csum(skb, l4_off, nexthdr) : NULL;
	if (csum) {
		inet_proto_csum_replace16(csum, skb, old_da.s6_addr32,
					  nh->s6_addr32, true);
		/* A real UDPv6 checksum of 0x0000 is illegal, replace it
		 * with 0xffff.  inet_proto_csum_replace16() keeps skb->csum
		 * consistent for CHECKSUM_COMPLETE because the IPv6 DA diff
		 * and the L4 csum diff cancel each other.
		 */
		if (nexthdr == IPPROTO_UDP && !*csum)
			*csum = CSUM_MANGLED_0;
	} else if (skb->ip_summed == CHECKSUM_COMPLETE) {
		update_csum_diff16(skb, old_da.s6_addr32, (__be32 *)nh);
	}

	ip6h->daddr = *nh;
	skb_clear_hash(skb);

	return 0;
}

/* seg6_lookup_nexthop() releases the original dst itself, so no
 * skb_dst_drop() is needed before the call.
 */
static int seg6_mobile_forward(struct sk_buff *skb)
{
	seg6_lookup_nexthop(skb, NULL, 0);
	return dst_input(skb);
}

static int input_action_end_map(struct sk_buff *skb,
				struct seg6_mobile_lwt *slwt)
{
	enum seg6_mobile_srh_state srh_state;

	seg6_mobile_get_and_validate_srh(skb, &srh_state);
	if (srh_state == SEG6_MOBILE_SRH_MALFORMED)
		goto drop;

	if (seg6_mobile_advance_da(skb, &slwt->nh6,
				   srh_state == SEG6_MOBILE_SRH_PRESENT))
		goto drop;

	return seg6_mobile_forward(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* Args.Mob.Session: 40-bit field laid out as
 * QFI(6) | R(1) | U(1) | PDU Session ID(32).
 */
#define SEG6_MOBILE_ARGS_MOB_LEN	40
#define SEG6_MOBILE_ARGS_QFI_SHIFT	58
#define SEG6_MOBILE_ARGS_TEID_SHIFT	24

/* GTPv1-U mandatory header flags: Version=1 (bits 7..5 = 001) +
 * Protocol Type=1 (bit 4); E/S/PN bits are clear by default.
 * GTP1_F_EXTHDR is ORed in by the caller when a PDU Session extension
 * header follows.
 */
#define SEG6_MOBILE_GTP1U_FLAGS_BASE	0x30

/* GTP-U PDU Session extension header.  Minimum 4-byte unit:
 * ext_len = 1, PDU Type in high 4 bits of @pdu_type_spare, QFI in
 * low 6 bits of @spare_qfi, next_ext = 0.
 */
struct seg6_mobile_pdu_session_ext {
	__u8	ext_len;
	__u8	pdu_type_spare;
	__u8	spare_qfi;
	__u8	next_ext;
};

#define SEG6_MOBILE_PDU_SESSION_NH		0x85
#define SEG6_MOBILE_PDU_SESSION_QFI_MASK	0x3f
#define SEG6_MOBILE_V6_SRC_PREFIX_LEN_DEFAULT	64

/* Read @nbits from a 16-byte big-endian @addr at bit offset @bit_off,
 * returned left-justified in 64 bits.  Caller ensures
 * bit_off + nbits <= 128 and 1 <= nbits <= 64.
 */
static u64 seg6_mobile_addr_get_bits(const u8 *addr, unsigned int bit_off,
				     unsigned int nbits)
{
	u64 hi = get_unaligned_be64(addr);
	u64 lo = get_unaligned_be64(addr + 8);
	u64 v;

	if (bit_off == 0)
		v = hi;
	else if (bit_off < 64)
		v = (hi << bit_off) | (lo >> (64 - bit_off));
	else
		v = lo << (bit_off - 64);

	return v & GENMASK_ULL(63, 64 - nbits);
}

/* Extract the IPv4 DA and Args.Mob.Session from an End.M.GTP4.E SID,
 * where the SR Gateway locator occupies the leading @locator_bits
 * bits of the IPv6 destination, the IPv4 DA the next 32 bits, and
 * Args.Mob.Session the 40 bits that follow it (RFC 9433).
 * seg6_mobile_v4_validate() guarantees the three fields fit in 128
 * bits at build time.
 */
static void seg6_mobile_parse_gtp4_sid(const struct in6_addr *daddr,
				       unsigned int locator_bits,
				       __be32 *v4_da, u64 *args_mob)
{
	u64 da_field;

	da_field = seg6_mobile_addr_get_bits(daddr->s6_addr, locator_bits, 32);
	*v4_da = htonl((u32)(da_field >> 32));

	*args_mob = seg6_mobile_addr_get_bits(daddr->s6_addr,
					      locator_bits + 32,
					      SEG6_MOBILE_ARGS_MOB_LEN);
}

/* Recover the IPv4 source address (RFC 9433): exactly 32 bits taken
 * from the inbound IPv6 SA at bit offset @v6_src_prefix_len (or /64
 * when unset).  The trailing bits are "any bit pattern (ignored)" and
 * are not read.
 */
static __be32 seg6_mobile_v4_sa(const struct in6_addr *ip6_sa,
				u8 v6_src_prefix_len)
{
	u8 p_bits = v6_src_prefix_len ? : SEG6_MOBILE_V6_SRC_PREFIX_LEN_DEFAULT;
	u64 sa_field;

	sa_field = seg6_mobile_addr_get_bits(ip6_sa->s6_addr, p_bits, 32);
	return htonl((u32)(sa_field >> 32));
}

static u8 seg6_mobile_qfi_from_args(u64 args_mob)
{
	return (args_mob >> SEG6_MOBILE_ARGS_QFI_SHIFT) &
	       SEG6_MOBILE_PDU_SESSION_QFI_MASK;
}

static u32 seg6_mobile_teid_from_args(u64 args_mob)
{
	return lower_32_bits(args_mob >> SEG6_MOBILE_ARGS_TEID_SHIFT);
}

/* Push a GTP-U header on top of @skb.  When @pdu_type_set is true the
 * GTPv1 long header (with the EH bit set) is followed by a 4-byte
 * PDU Session extension header; @pdu_type selects the PDU Type field
 * (0 for downlink, 1 for uplink, 2..15 reserved).  When
 * @pdu_type_set is false the GTPv1 short header is emitted with no
 * PDU Session, regardless of @qfi.
 */
static void seg6_mobile_push_gtpu(struct sk_buff *skb, u32 teid, u8 qfi,
				  u8 pdu_type, bool pdu_type_set)
{
	struct seg6_mobile_pdu_session_ext *pdu_session;
	struct gtp1_header_long *gtphl;
	struct gtp1_header *gtph;

	if (!pdu_type_set) {
		gtph = skb_push(skb, sizeof(*gtph));
		gtph->flags = SEG6_MOBILE_GTP1U_FLAGS_BASE;
		gtph->type = GTP_TPDU;
		gtph->length = htons(skb->len - sizeof(*gtph));
		gtph->tid = htonl(teid);
		return;
	}

	pdu_session = skb_push(skb, sizeof(*pdu_session));
	pdu_session->ext_len = 1;
	pdu_session->pdu_type_spare = (pdu_type & 0xf) << 4;
	pdu_session->spare_qfi = qfi & SEG6_MOBILE_PDU_SESSION_QFI_MASK;
	pdu_session->next_ext = 0;

	gtphl = skb_push(skb, sizeof(*gtphl));
	gtphl->flags = SEG6_MOBILE_GTP1U_FLAGS_BASE | GTP1_F_EXTHDR;
	gtphl->type = GTP_TPDU;
	gtphl->length = htons(skb->len - sizeof(struct gtp1_header));
	gtphl->tid = htonl(teid);
	gtphl->seq = 0;
	gtphl->npdu = 0;
	gtphl->next = SEG6_MOBILE_PDU_SESSION_NH;
}

/* Build the outer IPv4 + UDP + GTPv1-U[+PDU Session] header chain on
 * @skb and ship it via the IPv4 input path.  The IPv6 outer and its
 * extension headers must already have been popped.
 */
static int seg6_mobile_xmit_gtp4_e(struct net *net, struct sk_buff *skb,
				   struct seg6_mobile_lwt *slwt,
				   __be32 v4_sa, __be32 v4_da, u32 teid,
				   u8 qfi, __be16 inner_proto, u8 outer_tclass,
				   u8 outer_hoplimit)
{
	enum skb_drop_reason reason;
	unsigned int inner_nhlen;
	struct udphdr *uh;
	struct iphdr *iph;
	int err;

	if (skb_cow_head(skb,
			 sizeof(*iph) + sizeof(*uh) +
			 sizeof(struct gtp1_header_long) +
			 sizeof(struct seg6_mobile_pdu_session_ext)))
		return -ENOMEM;

	/* A GSO T-PDU must be re-segmented through the UDP-tunnel path once
	 * the outer IPv4/UDP/GTP-U chain is prepended, otherwise the GSO
	 * engine cannot find the inner transport header and drops it.  Mark
	 * the skb encapsulated and snapshot the inner IP headers so the
	 * segmenter emits one GTP-U packet per inner segment.  Non-GSO
	 * T-PDUs need none of this and are shipped as-is.
	 */
	if (inner_proto && skb_is_gso(skb)) {
		if (inner_proto == htons(ETH_P_IP)) {
			if (!pskb_may_pull(skb, sizeof(struct iphdr)))
				return -ENOMEM;
			inner_nhlen = ip_hdrlen(skb);
		} else {
			inner_nhlen = sizeof(struct ipv6hdr);
		}
		skb_set_transport_header(skb, inner_nhlen);
		skb_reset_mac_header(skb);
		err = iptunnel_handle_offloads(skb, SKB_GSO_UDP_TUNNEL);
		if (err)
			return err;
		skb_set_inner_protocol(skb, inner_proto);
	}

	seg6_mobile_push_gtpu(skb, teid, qfi, slwt->pdu_type,
			      slwt->pdu_type_set);

	uh = skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh->source = htons(GTP1U_PORT);
	uh->dest = htons(GTP1U_PORT);
	uh->len = htons(skb->len);
	uh->check = 0;

	iph = skb_push(skb, sizeof(*iph));
	skb_reset_network_header(skb);
	iph->version = 4;
	iph->ihl = sizeof(*iph) >> 2;
	iph->tos = outer_tclass;
	iph->tot_len = htons(skb->len);
	iph->frag_off = htons(IP_DF);
	iph->ttl = outer_hoplimit;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = v4_sa;
	iph->daddr = v4_da;
	__ip_select_ident(net, iph, 1);
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

	skb->protocol = htons(ETH_P_IP);
	nf_reset_ct(skb);
	skb_dst_drop(skb);

	/* Resolve the egress route on the input path and hand the packet
	 * to dst_input() so it traverses NF_INET_PRE_ROUTING and
	 * NF_INET_FORWARD like every other transformed MUP packet,
	 * keeping iptables/nftables FORWARD rules effective.  The IPv4
	 * source is synthesised from the IPv6 SA and has no reverse
	 * route, so operators must disable rp_filter on the ingress
	 * device (net.ipv4.conf.<dev>.rp_filter=0) for this behavior.
	 */
	reason = ip_route_input(skb, v4_da, v4_sa,
				inet_dsfield_to_dscp(outer_tclass), skb->dev);
	if (reason) {
		kfree_skb_reason(skb, reason);
		return -EINVAL;
	}
	return dst_input(skb);
}

/* decapsulate the SRv6 outer and emit IPv4/UDP/GTPv1-U */
static int input_action_end_m_gtp4_e(struct sk_buff *skb,
				     struct seg6_mobile_lwt *slwt)
{
	enum seg6_mobile_srh_state srh_state;
	struct net *net = dev_net(skb->dev);
	struct ipv6_sr_hdr *srh;
	unsigned int outer_len;
	struct in6_addr ip6_sa;
	struct ipv6hdr *ip6h;
	__be32 v4_da, v4_sa;
	__be16 inner_proto;
	u8 outer_hoplimit;
	__be16 frag_off;
	u8 outer_tclass;
	u64 args_mob;
	u32 teid;
	int off;
	u8 qfi;
	u8 nh;

	if (!pskb_may_pull(skb, sizeof(*ip6h)))
		goto drop;

	ip6h = ipv6_hdr(skb);
	ip6_sa = ip6h->saddr;
	outer_tclass = ipv6_get_dsfield(ip6h);
	outer_hoplimit = ip6h->hop_limit;

	seg6_mobile_parse_gtp4_sid(&ip6h->daddr, slwt->sr_prefix_len,
				   &v4_da, &args_mob);

	srh = seg6_mobile_get_and_validate_srh(skb, &srh_state);
	if (srh_state == SEG6_MOBILE_SRH_MALFORMED)
		goto drop;
	if (srh && srh->segments_left != 0)
		goto drop;

	/* @ip6h may have been invalidated by pskb_may_pull() inside
	 * seg6_mobile_get_and_validate_srh(); re-evaluate before any
	 * further dereference.
	 */
	ip6h = ipv6_hdr(skb);

	teid = seg6_mobile_teid_from_args(args_mob);
	qfi = seg6_mobile_qfi_from_args(args_mob);
	v4_sa = seg6_mobile_v4_sa(&ip6_sa, slwt->v6_src_prefix_len);

	nh = ip6h->nexthdr;
	off = ipv6_skip_exthdr(skb, sizeof(*ip6h), &nh, &frag_off);
	if (off < 0 || frag_off)
		goto drop;
	outer_len = off;

	/* Only an inner IP PDU (the encapsulated T-PDU) can be GSO and thus
	 * needs UDP-tunnel offload set up before encapsulation; any other
	 * upper-layer payload is shipped without it.
	 */
	switch (nh) {
	case IPPROTO_IPIP:
		inner_proto = htons(ETH_P_IP);
		break;
	case IPPROTO_IPV6:
		inner_proto = htons(ETH_P_IPV6);
		break;
	default:
		inner_proto = 0;
		break;
	}

	skb_pull_rcsum(skb, outer_len);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	if (seg6_mobile_xmit_gtp4_e(net, skb, slwt, v4_sa, v4_da, teid, qfi,
				    inner_proto, outer_tclass, outer_hoplimit))
		return -EINVAL;
	return 0;

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* Build the outer IPv6 + UDP + GTPv1-U[+PDU Session] header chain on
 * @skb and ship it via the IPv6 input path.  The IPv6 outer and its
 * extension headers must already have been popped.  The pseudo-header
 * sum is seeded here and CHECKSUM_PARTIAL is used so the stack or NIC
 * can complete the mandatory UDPv6 checksum.
 */
static int seg6_mobile_xmit_gtp6_e(struct sk_buff *skb,
				   struct seg6_mobile_lwt *slwt,
				   const struct in6_addr *v6_sa,
				   const struct in6_addr *v6_da, u32 teid,
				   u8 qfi, __be16 inner_proto, u8 outer_tclass,
				   u8 outer_hoplimit, __be32 flowlabel)
{
	unsigned int inner_nhlen;
	struct ipv6hdr *ip6h;
	struct udphdr *uh;
	unsigned int len;
	int err;

	if (skb_cow_head(skb,
			 sizeof(*ip6h) + sizeof(*uh) +
			 sizeof(struct gtp1_header_long) +
			 sizeof(struct seg6_mobile_pdu_session_ext)))
		return -ENOMEM;

	/* A GSO T-PDU must be re-segmented through the UDP-tunnel path once
	 * the outer IPv6/UDP/GTP-U chain is prepended, otherwise the GSO
	 * engine cannot find the inner transport header and drops it.  Mark
	 * the skb encapsulated and snapshot the inner IP headers so the
	 * segmenter emits one GTP-U packet per inner segment.  The outer
	 * UDPv6 checksum is mandatory, so request SKB_GSO_UDP_TUNNEL_CSUM and
	 * let skb_udp_tunnel_segment() complete it per segment.  Non-GSO
	 * T-PDUs need none of this and are shipped as-is.
	 */
	if (inner_proto && skb_is_gso(skb)) {
		if (inner_proto == htons(ETH_P_IP)) {
			if (!pskb_may_pull(skb, sizeof(struct iphdr)))
				return -ENOMEM;
			inner_nhlen = ip_hdrlen(skb);
		} else {
			inner_nhlen = sizeof(struct ipv6hdr);
		}
		skb_set_transport_header(skb, inner_nhlen);
		skb_reset_mac_header(skb);
		err = iptunnel_handle_offloads(skb, SKB_GSO_UDP_TUNNEL_CSUM);
		if (err)
			return err;
		skb_set_inner_protocol(skb, inner_proto);
	}

	seg6_mobile_push_gtpu(skb, teid, qfi, slwt->pdu_type,
			      slwt->pdu_type_set);

	uh = skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh->source = htons(GTP1U_PORT);
	uh->dest = htons(GTP1U_PORT);
	uh->len = htons(skb->len);

	ip6h = skb_push(skb, sizeof(*ip6h));
	skb_reset_network_header(skb);
	memset(ip6h, 0, sizeof(*ip6h));
	ip6_flow_hdr(ip6h, outer_tclass, flowlabel);
	len = skb->len - sizeof(*ip6h);
	ip6h->payload_len = htons(len);
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = outer_hoplimit;
	ip6h->saddr = *v6_sa;
	ip6h->daddr = *v6_da;

	/* UDP checksum over IPv6 must be non-zero.  udp6_set_csum() seeds
	 * the pseudo-header sum: a GSO skb keeps its inner CHECKSUM_PARTIAL
	 * offload intact and skb_udp_tunnel_segment() folds the outer
	 * checksum per segment; a non-GSO skb hands the outer checksum to
	 * the stack or NIC via CHECKSUM_PARTIAL (or resolves an inner
	 * CHECKSUM_PARTIAL via local checksum offload).
	 */
	udp6_set_csum(false, skb, v6_sa, v6_da, len);

	skb->protocol = htons(ETH_P_IPV6);
	nf_reset_ct(skb);

	/* Resolve the egress route on the input path and hand the packet
	 * to dst_input() so it traverses NF_INET_PRE_ROUTING and
	 * NF_INET_FORWARD like every other transformed MUP packet,
	 * keeping ip6tables/nftables FORWARD rules effective.  The outer
	 * IPv6 source is the operator-configured slwt->src_addr with a
	 * normal reverse route, so unlike End.M.GTP4.E this needs no
	 * rp_filter relaxation.
	 */
	ip6_route_input(skb);
	return dst_input(skb);
}

/* terminate the SRv6 packet and emit IPv6/UDP/GTPv1-U */
static int input_action_end_m_gtp6_e(struct sk_buff *skb,
				     struct seg6_mobile_lwt *slwt)
{
	enum seg6_mobile_srh_state srh_state;
	struct ipv6_sr_hdr *srh;
	unsigned int outer_len;
	struct in6_addr ip6_da;
	struct ipv6hdr *ip6h;
	__be16 inner_proto;
	u8 outer_hoplimit;
	__be32 flowlabel;
	__be16 frag_off;
	u8 outer_tclass;
	u64 args_mob;
	u32 teid;
	int off;
	u8 qfi;
	u8 nh;

	srh = seg6_mobile_get_and_validate_srh(skb, &srh_state);
	if (srh_state != SEG6_MOBILE_SRH_PRESENT)
		goto drop;

	/* End.M.GTP6.E is always the penultimate segment; active only
	 * when segments_left == 1.
	 */
	if (srh->segments_left != 1)
		goto drop;

	if (!pskb_may_pull(skb, sizeof(*ip6h)))
		goto drop;

	ip6h = ipv6_hdr(skb);

	/* parse_nla_sr_prefix_len() guarantees the locator leaves room
	 * for the 40-bit Args.Mob.Session.
	 */
	args_mob = seg6_mobile_addr_get_bits(ip6h->daddr.s6_addr,
					     slwt->sr_prefix_len,
					     SEG6_MOBILE_ARGS_MOB_LEN);
	teid = seg6_mobile_teid_from_args(args_mob);
	qfi = seg6_mobile_qfi_from_args(args_mob);
	ip6_da = srh->segments[0];
	outer_tclass = ipv6_get_dsfield(ip6h);
	outer_hoplimit = ip6h->hop_limit;
	flowlabel = ip6_flowlabel(ip6h);

	nh = ip6h->nexthdr;
	off = ipv6_skip_exthdr(skb, sizeof(*ip6h), &nh, &frag_off);
	if (off < 0 || frag_off)
		goto drop;
	outer_len = off;

	/* Only an inner IP PDU (the encapsulated T-PDU) can be GSO and thus
	 * needs UDP-tunnel offload set up before encapsulation; any other
	 * upper-layer payload is shipped without it.
	 */
	switch (nh) {
	case IPPROTO_IPIP:
		inner_proto = htons(ETH_P_IP);
		break;
	case IPPROTO_IPV6:
		inner_proto = htons(ETH_P_IPV6);
		break;
	default:
		inner_proto = 0;
		break;
	}

	skb_pull_rcsum(skb, outer_len);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	if (seg6_mobile_xmit_gtp6_e(skb, slwt, &slwt->src_addr, &ip6_da,
				    teid, qfi, inner_proto, outer_tclass,
				    outer_hoplimit, flowlabel))
		return -EINVAL;
	return 0;

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* Cross-attribute sanity check shared by the GTP4 actions (End.M.GTP4.E
 * and H.M.GTP4.D).  Both fit two fields into the 128-bit IPv6 address:
 *  - the IPv4 source template, anchored at the Source UPF Prefix length P
 *    (= the configured v6_src_prefix_len, or
 *    SEG6_MOBILE_V6_SRC_PREFIX_LEN_DEFAULT when unset), needs P + 32 bits;
 *  - the SID locator (sr_prefix_len), the 32-bit IPv4 DA, and the 40-bit
 *    Args.Mob.Session must together fit in 128 bits.
 */
static int seg6_mobile_v4_validate(struct seg6_mobile_lwt *slwt,
				   struct netlink_ext_ack *extack)
{
	u8 p_bits = slwt->v6_src_prefix_len ? :
		    SEG6_MOBILE_V6_SRC_PREFIX_LEN_DEFAULT;

	if (p_bits + 32 > 128) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile v6_src_prefix_len must leave room for the 32-bit IPv4 source template (prefix_len <= 96)");
		return -EINVAL;
	}

	if (slwt->sr_prefix_len + 32 + SEG6_MOBILE_ARGS_MOB_LEN > 128) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile sr_prefix_len + 32 (IPv4 DA) + 40 (Args.Mob.Session) must not exceed 128");
		return -EINVAL;
	}
	return 0;
}

/* End.M.GTP4.E is a downlink interworking behavior toward a legacy gNB, so
 * it only carries downlink T-PDUs.  Restrict it to PDU Type 0 (downlink);
 * the uplink PDU Type is served by the End.M.GTP6.E family.  The common
 * parser already rejects the reserved 2..15 values.
 */
static int seg6_mobile_end_m_gtp4_e_validate(struct seg6_mobile_lwt *slwt,
					     struct netlink_ext_ack *extack)
{
	int err;

	err = seg6_mobile_v4_validate(slwt, extack);
	if (err < 0)
		return err;

	if (slwt->pdu_type_set && slwt->pdu_type != 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile End.M.GTP4.E supports PDU Type 0 (DL) only");
		return -EINVAL;
	}
	return 0;
}

static int parse_nla_nh6(struct nlattr **attrs, struct seg6_mobile_lwt *slwt,
			 struct netlink_ext_ack *extack)
{
	memcpy(&slwt->nh6, nla_data(attrs[SEG6_MOBILE_NH6]),
	       sizeof(struct in6_addr));

	return 0;
}

static int put_nla_nh6(struct sk_buff *skb, struct seg6_mobile_lwt *slwt)
{
	if (nla_put_in6_addr(skb, SEG6_MOBILE_NH6, &slwt->nh6))
		return -EMSGSIZE;

	return 0;
}

static int cmp_nla_nh6(struct seg6_mobile_lwt *a, struct seg6_mobile_lwt *b)
{
	return memcmp(&a->nh6, &b->nh6, sizeof(struct in6_addr));
}

static int parse_nla_src_addr(struct nlattr **attrs,
			      struct seg6_mobile_lwt *slwt,
			      struct netlink_ext_ack *extack)
{
	memcpy(&slwt->src_addr, nla_data(attrs[SEG6_MOBILE_SRC_ADDR]),
	       sizeof(struct in6_addr));
	return 0;
}

static int put_nla_src_addr(struct sk_buff *skb,
			    struct seg6_mobile_lwt *slwt)
{
	if (nla_put_in6_addr(skb, SEG6_MOBILE_SRC_ADDR, &slwt->src_addr))
		return -EMSGSIZE;
	return 0;
}

static int cmp_nla_src_addr(struct seg6_mobile_lwt *a,
			    struct seg6_mobile_lwt *b)
{
	return memcmp(&a->src_addr, &b->src_addr, sizeof(struct in6_addr));
}

static int parse_nla_pdu_type(struct nlattr **attrs,
			      struct seg6_mobile_lwt *slwt,
			      struct netlink_ext_ack *extack)
{
	u8 t = nla_get_u8(attrs[SEG6_MOBILE_PDU_TYPE]);

	/* Only PDU Type 0 (downlink) and 1 (uplink) are defined; 2..15
	 * are reserved.  Reject reserved values rather than writing them
	 * onto the wire, since the UAPI cannot be tightened after merge.
	 */
	if (t > 0x1) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile PDU Type must be 0 (DL) or 1 (UL); 2..15 are reserved");
		return -EINVAL;
	}
	slwt->pdu_type = t;
	slwt->pdu_type_set = true;
	return 0;
}

static int put_nla_pdu_type(struct sk_buff *skb,
			    struct seg6_mobile_lwt *slwt)
{
	if (nla_put_u8(skb, SEG6_MOBILE_PDU_TYPE, slwt->pdu_type))
		return -EMSGSIZE;
	return 0;
}

static int cmp_nla_pdu_type(struct seg6_mobile_lwt *a,
			    struct seg6_mobile_lwt *b)
{
	return a->pdu_type != b->pdu_type;
}

static int parse_nla_v6_src_prefix_len(struct nlattr **attrs,
				       struct seg6_mobile_lwt *slwt,
				       struct netlink_ext_ack *extack)
{
	u8 len = nla_get_u8(attrs[SEG6_MOBILE_V6_SRC_PREFIX_LEN]);

	if (len == 0 || len > 127) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile v6_src_prefix_len must be in 1..127");
		return -EINVAL;
	}
	slwt->v6_src_prefix_len = len;
	return 0;
}

static int put_nla_v6_src_prefix_len(struct sk_buff *skb,
				     struct seg6_mobile_lwt *slwt)
{
	if (nla_put_u8(skb, SEG6_MOBILE_V6_SRC_PREFIX_LEN,
		       slwt->v6_src_prefix_len))
		return -EMSGSIZE;
	return 0;
}

static int cmp_nla_v6_src_prefix_len(struct seg6_mobile_lwt *a,
				     struct seg6_mobile_lwt *b)
{
	return a->v6_src_prefix_len != b->v6_src_prefix_len;
}

static int parse_nla_sr_prefix_len(struct nlattr **attrs,
				   struct seg6_mobile_lwt *slwt,
				   struct netlink_ext_ack *extack)
{
	u8 len = nla_get_u8(attrs[SEG6_MOBILE_SR_PREFIX_LEN]);

	/* The locator must be non-zero and leave room for the 40-bit
	 * Args.Mob.Session that the behavior stamps right after it.
	 */
	if (len == 0 || len + SEG6_MOBILE_ARGS_MOB_LEN > 128) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile sr_prefix_len must be in 1..88 (leaving room for the 40-bit Args.Mob.Session)");
		return -EINVAL;
	}
	slwt->sr_prefix_len = len;
	return 0;
}

static int put_nla_sr_prefix_len(struct sk_buff *skb,
				 struct seg6_mobile_lwt *slwt)
{
	if (nla_put_u8(skb, SEG6_MOBILE_SR_PREFIX_LEN, slwt->sr_prefix_len))
		return -EMSGSIZE;
	return 0;
}

static int cmp_nla_sr_prefix_len(struct seg6_mobile_lwt *a,
				 struct seg6_mobile_lwt *b)
{
	return a->sr_prefix_len != b->sr_prefix_len;
}

static const struct
nla_policy seg6_mobile_counters_policy[SEG6_MOBILE_CNT_MAX + 1] = {
	[SEG6_MOBILE_CNT_PACKETS]	= { .type = NLA_U64 },
	[SEG6_MOBILE_CNT_BYTES]		= { .type = NLA_U64 },
	[SEG6_MOBILE_CNT_ERRORS]	= { .type = NLA_U64 },
};

static int parse_nla_counters(struct nlattr **attrs,
			      struct seg6_mobile_lwt *slwt,
			      struct netlink_ext_ack *extack)
{
	struct pcpu_seg6_mobile_counters __percpu *pcounters;
	struct nlattr *tb[SEG6_MOBILE_CNT_MAX + 1];
	int ret;

	ret = nla_parse_nested_deprecated(tb, SEG6_MOBILE_CNT_MAX,
					  attrs[SEG6_MOBILE_COUNTERS],
					  seg6_mobile_counters_policy, extack);
	if (ret < 0)
		return ret;

	/* basic support for SRv6 Behavior counters requires at least:
	 * packets, bytes and errors.
	 */
	if (!tb[SEG6_MOBILE_CNT_PACKETS] || !tb[SEG6_MOBILE_CNT_BYTES] ||
	    !tb[SEG6_MOBILE_CNT_ERRORS])
		return -EINVAL;

	/* counters are always zero initialized */
	pcounters = seg6_mobile_alloc_pcpu_counters(GFP_KERNEL);
	if (!pcounters)
		return -ENOMEM;

	slwt->pcpu_counters = pcounters;

	return 0;
}

static int seg6_mobile_fill_nla_counters(struct sk_buff *skb,
					 struct seg6_mobile_counters *counters)
{
	if (nla_put_u64_64bit(skb, SEG6_MOBILE_CNT_PACKETS, counters->packets,
			      SEG6_MOBILE_CNT_PAD))
		return -EMSGSIZE;

	if (nla_put_u64_64bit(skb, SEG6_MOBILE_CNT_BYTES, counters->bytes,
			      SEG6_MOBILE_CNT_PAD))
		return -EMSGSIZE;

	if (nla_put_u64_64bit(skb, SEG6_MOBILE_CNT_ERRORS, counters->errors,
			      SEG6_MOBILE_CNT_PAD))
		return -EMSGSIZE;

	return 0;
}

static int put_nla_counters(struct sk_buff *skb, struct seg6_mobile_lwt *slwt)
{
	struct seg6_mobile_counters counters = { 0, 0, 0 };
	struct nlattr *nest;
	int rc, i;

	nest = nla_nest_start(skb, SEG6_MOBILE_COUNTERS);
	if (!nest)
		return -EMSGSIZE;

	for_each_possible_cpu(i) {
		struct pcpu_seg6_mobile_counters *pcounters;
		u64 packets, bytes, errors;
		unsigned int start;

		pcounters = per_cpu_ptr(slwt->pcpu_counters, i);
		do {
			start = u64_stats_fetch_begin(&pcounters->syncp);

			packets = u64_stats_read(&pcounters->packets);
			bytes = u64_stats_read(&pcounters->bytes);
			errors = u64_stats_read(&pcounters->errors);

		} while (u64_stats_fetch_retry(&pcounters->syncp, start));

		counters.packets += packets;
		counters.bytes += bytes;
		counters.errors += errors;
	}

	rc = seg6_mobile_fill_nla_counters(skb, &counters);
	if (rc < 0) {
		nla_nest_cancel(skb, nest);
		return rc;
	}

	return nla_nest_end(skb, nest);
}

static int cmp_nla_counters(struct seg6_mobile_lwt *a,
			    struct seg6_mobile_lwt *b)
{
	/* tunnels with counters enabled and disabled are different. */
	return (!!((unsigned long)a->pcpu_counters)) ^
		(!!((unsigned long)b->pcpu_counters));
}

static void destroy_attr_counters(struct seg6_mobile_lwt *slwt)
{
	free_percpu(slwt->pcpu_counters);
}

static const struct seg6_mobile_action_desc seg6_mobile_action_table[] = {
	{
		.action		= SEG6_MOBILE_ACTION_END_MAP,
		.attrs		= SEG6_MOBILE_F_ATTR(SEG6_MOBILE_NH6),
		.optattrs	= SEG6_F_MOBILE_COUNTERS,
		.input		= input_action_end_map,
	},
	{
		.action		= SEG6_MOBILE_ACTION_END_M_GTP4_E,
		.attrs		= SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SR_PREFIX_LEN),
		.optattrs	= SEG6_F_MOBILE_COUNTERS |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_PDU_TYPE) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_V6_SRC_PREFIX_LEN),
		.input		= input_action_end_m_gtp4_e,
		.validate	= seg6_mobile_end_m_gtp4_e_validate,
	},
	{
		.action		= SEG6_MOBILE_ACTION_END_M_GTP6_E,
		.attrs		= SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRC_ADDR) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SR_PREFIX_LEN),
		.optattrs	= SEG6_F_MOBILE_COUNTERS |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_PDU_TYPE),
		.input		= input_action_end_m_gtp6_e,
	},
};

static const struct seg6_mobile_action_param
seg6_mobile_action_params[SEG6_MOBILE_MAX + 1] = {
	[SEG6_MOBILE_NH6] = {
		.parse	= parse_nla_nh6,
		.put	= put_nla_nh6,
		.cmp	= cmp_nla_nh6,
	},
	[SEG6_MOBILE_COUNTERS] = {
		.parse		= parse_nla_counters,
		.put		= put_nla_counters,
		.cmp		= cmp_nla_counters,
		.destroy	= destroy_attr_counters,
	},
	[SEG6_MOBILE_SRC_ADDR] = {
		.parse	= parse_nla_src_addr,
		.put	= put_nla_src_addr,
		.cmp	= cmp_nla_src_addr,
	},
	[SEG6_MOBILE_PDU_TYPE] = {
		.parse	= parse_nla_pdu_type,
		.put	= put_nla_pdu_type,
		.cmp	= cmp_nla_pdu_type,
	},
	[SEG6_MOBILE_V6_SRC_PREFIX_LEN] = {
		.parse	= parse_nla_v6_src_prefix_len,
		.put	= put_nla_v6_src_prefix_len,
		.cmp	= cmp_nla_v6_src_prefix_len,
	},
	[SEG6_MOBILE_SR_PREFIX_LEN] = {
		.parse	= parse_nla_sr_prefix_len,
		.put	= put_nla_sr_prefix_len,
		.cmp	= cmp_nla_sr_prefix_len,
	},
};

static const struct nla_policy
seg6_mobile_policy[SEG6_MOBILE_MAX + 1] = {
	[SEG6_MOBILE_ACTION]		= { .type = NLA_U32 },
	[SEG6_MOBILE_NH6]		= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[SEG6_MOBILE_COUNTERS]		= { .type = NLA_NESTED },
	[SEG6_MOBILE_SRC_ADDR]		= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[SEG6_MOBILE_PDU_TYPE]		= { .type = NLA_U8 },
	[SEG6_MOBILE_V6_SRC_PREFIX_LEN]	= { .type = NLA_U8 },
	[SEG6_MOBILE_SR_PREFIX_LEN]	= { .type = NLA_U8 },
};

static const struct seg6_mobile_action_desc *
seg6_mobile_get_action_desc(int action)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(seg6_mobile_action_table); i++) {
		if (seg6_mobile_action_table[i].action == action)
			return &seg6_mobile_action_table[i];
	}

	return NULL;
}

/* call the destroy() callback (if available) for each set attribute in
 * @parsed_attrs, starting from the first attribute up to the @max_parsed
 * (excluded) attribute.
 */
static void __destroy_attrs(unsigned long parsed_attrs, int max_parsed,
			    struct seg6_mobile_lwt *slwt)
{
	const struct seg6_mobile_action_param *param;
	int i;

	for (i = SEG6_MOBILE_ACTION + 1; i < max_parsed; i++) {
		if (!(parsed_attrs & SEG6_MOBILE_F_ATTR(i)))
			continue;

		param = &seg6_mobile_action_params[i];
		if (param->destroy)
			param->destroy(slwt);
	}
}

static void destroy_attrs(struct seg6_mobile_lwt *slwt)
{
	unsigned long attrs = slwt->desc->attrs | slwt->parsed_optattrs;

	__destroy_attrs(attrs, SEG6_MOBILE_MAX + 1, slwt);
}

static int seg6_mobile_parse_attrs(struct nlattr **attrs,
				   struct seg6_mobile_lwt *slwt,
				   struct netlink_ext_ack *extack)
{
	const struct seg6_mobile_action_param *param;
	const struct seg6_mobile_action_desc *desc;
	unsigned long parsed_optattrs = 0;
	int i, err;

	desc = slwt->desc;

	if (WARN_ON_ONCE(desc->attrs & desc->optattrs))
		return -EINVAL;

	for (i = SEG6_MOBILE_ACTION + 1; i <= SEG6_MOBILE_MAX; i++) {
		bool required = desc->attrs & SEG6_MOBILE_F_ATTR(i);
		bool optional = desc->optattrs & SEG6_MOBILE_F_ATTR(i);

		if (!required && !optional)
			continue;

		if (required && !attrs[i]) {
			NL_SET_ERR_MSG_MOD(extack,
					   "missing required attribute");
			err = -EINVAL;
			goto err;
		}

		if (!attrs[i])
			continue;

		param = &seg6_mobile_action_params[i];
		err = param->parse(attrs, slwt, extack);
		if (err < 0)
			goto err;

		if (optional)
			parsed_optattrs |= SEG6_MOBILE_F_ATTR(i);
	}

	slwt->parsed_optattrs = parsed_optattrs;

	return 0;

err:
	__destroy_attrs(desc->attrs | parsed_optattrs, i, slwt);
	return err;
}

static bool seg6_mobile_counters_enabled(struct seg6_mobile_lwt *slwt)
{
	return slwt->parsed_optattrs & SEG6_F_MOBILE_COUNTERS;
}

static void seg6_mobile_update_counters(struct seg6_mobile_lwt *slwt,
					unsigned int len, int err)
{
	struct pcpu_seg6_mobile_counters *pcounters;

	pcounters = this_cpu_ptr(slwt->pcpu_counters);
	u64_stats_update_begin(&pcounters->syncp);

	if (likely(!err)) {
		u64_stats_inc(&pcounters->packets);
		u64_stats_add(&pcounters->bytes, len);
	} else {
		u64_stats_inc(&pcounters->errors);
	}

	u64_stats_update_end(&pcounters->syncp);
}

static int seg6_mobile_input(struct sk_buff *skb)
{
	struct dst_entry *orig_dst = skb_dst(skb);
	struct seg6_mobile_lwt *slwt;
	unsigned int len = skb->len;
	int rc;

	if (skb->protocol != htons(ETH_P_IPV6)) {
		kfree_skb(skb);
		return -EINVAL;
	}

	slwt = seg6_mobile_lwtunnel(orig_dst->lwtstate);

	rc = slwt->desc->input(skb, slwt);

	if (seg6_mobile_counters_enabled(slwt))
		seg6_mobile_update_counters(slwt, len, rc);

	return rc;
}

static int seg6_mobile_build_state(struct net *net, struct nlattr *nla,
				   unsigned int family, const void *cfg,
				   struct lwtunnel_state **ts,
				   struct netlink_ext_ack *extack)
{
	const struct seg6_mobile_action_desc *desc;
	struct nlattr *tb[SEG6_MOBILE_MAX + 1];
	struct lwtunnel_state *newts;
	struct seg6_mobile_lwt *slwt;
	int err;

	if (family != AF_INET6)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, SEG6_MOBILE_MAX, nla,
					  seg6_mobile_policy, extack);
	if (err < 0)
		return err;

	if (!tb[SEG6_MOBILE_ACTION]) {
		NL_SET_ERR_MSG_MOD(extack, "missing SEG6_MOBILE_ACTION");
		return -EINVAL;
	}

	desc = seg6_mobile_get_action_desc(nla_get_u32(tb[SEG6_MOBILE_ACTION]));
	if (!desc) {
		NL_SET_ERR_MSG_MOD(extack, "unknown SRv6 Mobile action");
		return -EOPNOTSUPP;
	}

	newts = lwtunnel_state_alloc(sizeof(*slwt));
	if (!newts)
		return -ENOMEM;

	slwt = seg6_mobile_lwtunnel(newts);
	slwt->action = desc->action;
	slwt->desc = desc;

	err = seg6_mobile_parse_attrs(tb, slwt, extack);
	if (err < 0) {
		kfree(newts);
		return err;
	}

	if (desc->validate) {
		err = desc->validate(slwt, extack);
		if (err < 0) {
			destroy_attrs(slwt);
			kfree(newts);
			return err;
		}
	}

	newts->type = LWTUNNEL_ENCAP_SEG6_MOBILE;
	newts->flags = LWTUNNEL_STATE_INPUT_REDIRECT;

	*ts = newts;

	return 0;
}

static void seg6_mobile_destroy_state(struct lwtunnel_state *lwt)
{
	destroy_attrs(seg6_mobile_lwtunnel(lwt));
}

static int seg6_mobile_fill_encap(struct sk_buff *skb,
				  struct lwtunnel_state *lwt)
{
	struct seg6_mobile_lwt *slwt = seg6_mobile_lwtunnel(lwt);
	const struct seg6_mobile_action_param *param;
	unsigned long attrs;
	int i, err;

	if (nla_put_u32(skb, SEG6_MOBILE_ACTION, slwt->action))
		return -EMSGSIZE;

	attrs = slwt->desc->attrs | slwt->parsed_optattrs;
	for (i = SEG6_MOBILE_ACTION + 1; i <= SEG6_MOBILE_MAX; i++) {
		if (!(attrs & SEG6_MOBILE_F_ATTR(i)))
			continue;

		param = &seg6_mobile_action_params[i];
		err = param->put(skb, slwt);
		if (err < 0)
			return err;
	}

	return 0;
}

static int seg6_mobile_get_encap_size(struct lwtunnel_state *lwt)
{
	struct seg6_mobile_lwt *slwt = seg6_mobile_lwtunnel(lwt);
	unsigned long attrs;
	int nlsize;

	nlsize = nla_total_size(sizeof(u32)); /* SEG6_MOBILE_ACTION */

	attrs = slwt->desc->attrs | slwt->parsed_optattrs;
	if (attrs & SEG6_MOBILE_F_ATTR(SEG6_MOBILE_NH6))
		nlsize += nla_total_size(sizeof(struct in6_addr));

	if (attrs & SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRC_ADDR))
		nlsize += nla_total_size(sizeof(struct in6_addr));

	if (attrs & SEG6_MOBILE_F_ATTR(SEG6_MOBILE_PDU_TYPE))
		nlsize += nla_total_size(sizeof(u8));

	if (attrs & SEG6_MOBILE_F_ATTR(SEG6_MOBILE_V6_SRC_PREFIX_LEN))
		nlsize += nla_total_size(sizeof(u8));

	if (attrs & SEG6_F_MOBILE_COUNTERS)
		nlsize += nla_total_size(0) + /* nest SEG6_MOBILE_COUNTERS */
			  /* SEG6_MOBILE_CNT_PACKETS */
			  nla_total_size_64bit(sizeof(__u64)) +
			  /* SEG6_MOBILE_CNT_BYTES */
			  nla_total_size_64bit(sizeof(__u64)) +
			  /* SEG6_MOBILE_CNT_ERRORS */
			  nla_total_size_64bit(sizeof(__u64));

	return nlsize;
}

static int seg6_mobile_cmp_encap(struct lwtunnel_state *a,
				 struct lwtunnel_state *b)
{
	struct seg6_mobile_lwt *slwt_a = seg6_mobile_lwtunnel(a);
	struct seg6_mobile_lwt *slwt_b = seg6_mobile_lwtunnel(b);
	const struct seg6_mobile_action_param *param;
	unsigned long attrs_a, attrs_b;
	int i;

	if (slwt_a->action != slwt_b->action)
		return 1;

	attrs_a = slwt_a->desc->attrs | slwt_a->parsed_optattrs;
	attrs_b = slwt_b->desc->attrs | slwt_b->parsed_optattrs;

	if (attrs_a != attrs_b)
		return 1;

	for (i = SEG6_MOBILE_ACTION + 1; i <= SEG6_MOBILE_MAX; i++) {
		if (!(attrs_a & SEG6_MOBILE_F_ATTR(i)))
			continue;

		param = &seg6_mobile_action_params[i];
		if (param->cmp(slwt_a, slwt_b))
			return 1;
	}

	return 0;
}

static const struct lwtunnel_encap_ops seg6_mobile_ops = {
	.build_state	= seg6_mobile_build_state,
	.destroy_state	= seg6_mobile_destroy_state,
	.input		= seg6_mobile_input,
	.fill_encap	= seg6_mobile_fill_encap,
	.get_encap_size	= seg6_mobile_get_encap_size,
	.cmp_encap	= seg6_mobile_cmp_encap,
	.owner		= THIS_MODULE,
};

int __init seg6_mobile_init(void)
{
	BUILD_BUG_ON(SEG6_MOBILE_MAX + 1 > BITS_PER_TYPE(unsigned long));

	return lwtunnel_encap_add_ops(&seg6_mobile_ops,
				      LWTUNNEL_ENCAP_SEG6_MOBILE);
}

void seg6_mobile_exit(void)
{
	lwtunnel_encap_del_ops(&seg6_mobile_ops, LWTUNNEL_ENCAP_SEG6_MOBILE);
}
