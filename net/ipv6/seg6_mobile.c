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
#include <net/gso.h>
#include <net/gtp.h>
#include <net/ip.h>
#include <net/ip6_route.h>
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
	u8 v4_mask_len;
	u8 pdu_type;
	bool pdu_type_set;
	u8 v6_src_prefix_len;
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

/* Counterpart to seg6_local.c::get_and_validate_srh(), but returns a
 * 3-state result instead of NULL/srh.  End.MAP (RFC 9433 Section 6.2)
 * forwards SRH-less packets too, so the caller must distinguish
 * ABSENT (forward) from MALFORMED (drop); folding them into one NULL
 * return as seg6_local does is not sufficient here.
 *
 * The happy path reuses seg6.c::seg6_get_srh() without the
 * IP6_FH_F_SKIP_RH flag, so an SRH whose Segments Left has already
 * been decremented to zero (the terminal-SID case in RFC 9433
 * Section 6.6 et al.) is reported as PRESENT rather than spuriously
 * looking ABSENT.  When seg6_get_srh() returns NULL the failure is
 * reclassified by re-probing the extension chain for IPPROTO_ROUTING:
 * a clean -ENOENT means ABSENT, anything else (truncated chain,
 * invalid length, seg6_validate_srh failure) means MALFORMED.
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
 * protocols whose checksum does not cover the IPv6 pseudo-header (RFC
 * 8200 Section 8.1).
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

/* Rewrite the IPv6 destination address with @nh.  When the packet
 * carries the upper-layer header directly after the IPv6 header (no
 * extension headers) and the transport uses the IPv6 pseudo-header,
 * patch the L4 checksum by the DA diff.  When an extension-header
 * chain is present the receiver will continue processing it (e.g.
 * SRv6 routing restores DA to segments[0]) before delivering to L4,
 * so the original checksum stays valid and only skb->csum needs
 * maintenance for CHECKSUM_COMPLETE skbs.
 */
static int seg6_mobile_advance_da(struct sk_buff *skb,
				  const struct in6_addr *nh)
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

	if (!ipv6_ext_hdr(ip6h->nexthdr)) {
		nexthdr = ip6h->nexthdr;
		l4_off = ipv6_skip_exthdr(skb, sizeof(*ip6h), &nexthdr,
					  &frag_off);
		if (l4_off < 0)
			return -EINVAL;

		/* Non-first fragments do not carry the L4 header at
		 * @l4_off; only the first fragment is patched.
		 */
		if (frag_off == 0)
			l4_hlen = seg6_mobile_l4_csum_hlen(nexthdr);
		if (l4_hlen)
			write_len = l4_off + l4_hlen;
	}

	if (skb_ensure_writable(skb, write_len))
		return -ENOMEM;

	ip6h = ipv6_hdr(skb);
	old_da = ip6h->daddr;

	csum = l4_hlen ? seg6_mobile_l4_csum(skb, l4_off, nexthdr) : NULL;
	if (csum) {
		inet_proto_csum_replace16(csum, skb, old_da.s6_addr32,
					  nh->s6_addr32, true);
		/* RFC 8200 Section 8.1: a real UDPv6 checksum of 0x0000
		 * is illegal, replace it with 0xffff.
		 * inet_proto_csum_replace16() keeps skb->csum consistent
		 * for CHECKSUM_COMPLETE because the IPv6 DA diff and the
		 * L4 csum diff cancel each other.
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

/* RFC 9433 Section 6.2 -- End.MAP: replace the IPv6 destination with
 * the configured next SID and forward.  The SRH (if any) is preserved
 * so downstream segments still observe the original list; a malformed
 * SRH is dropped here rather than forwarded.
 */
static int input_action_end_map(struct sk_buff *skb,
				struct seg6_mobile_lwt *slwt)
{
	enum seg6_mobile_srh_state srh_state;

	seg6_mobile_get_and_validate_srh(skb, &srh_state);
	if (srh_state == SEG6_MOBILE_SRH_MALFORMED)
		goto drop;

	if (seg6_mobile_advance_da(skb, &slwt->nh6))
		goto drop;

	return seg6_mobile_forward(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* RFC 9433 Section 6.1 Figure 8: Args.Mob.Session is a 40-bit field
 * laid out as QFI(6) | R(1) | U(1) | PDU Session ID(32).
 */
#define SEG6_MOBILE_ARGS_MOB_LEN	40
#define SEG6_MOBILE_ARGS_QFI_SHIFT	58
#define SEG6_MOBILE_ARGS_TEID_SHIFT	24

/* GTPv1-U mandatory header flags: Version=1 (bits 7..5 = 001) +
 * Protocol Type=1 (bit 4); E/S/PN bits are clear by default (3GPP TS
 * 29.060 Figure 2 / Table 5).  GTP1_F_EXTHDR is ORed in by the caller
 * when a PDU Session extension header follows.
 */
#define SEG6_MOBILE_GTP1U_FLAGS_BASE	0x30

/* GTP-U PDU Session extension header (3GPP TS 38.415).  Minimum
 * 4-byte unit: ext_len = 1, PDU Type in high 4 bits of
 * @pdu_type_spare, QFI in low 6 bits of @spare_qfi, next_ext = 0.
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

static bool seg6_mobile_v4_mask_valid(u8 v4_mask_len)
{
	return v4_mask_len > 0 && v4_mask_len <= 32;
}

/* Extract the IPv4 DA and Args.Mob.Session from an End.M.GTP4.E SID,
 * where the SR Gateway locator occupies the leading @locator_bits
 * bits of the IPv6 destination, the IPv4 DA the next @v4_mask_len
 * bits, and Args.Mob.Session the 40 bits that follow it (RFC 9433
 * Section 6.6 Figure 9).
 */
static bool seg6_mobile_parse_gtp4_sid(const struct in6_addr *daddr,
				       unsigned int locator_bits,
				       u8 v4_mask_len,
				       __be32 *v4_da, u64 *args_mob)
{
	u64 da_field;

	if (!seg6_mobile_v4_mask_valid(v4_mask_len))
		return false;
	if (locator_bits + v4_mask_len + SEG6_MOBILE_ARGS_MOB_LEN > 128)
		return false;

	da_field = seg6_mobile_addr_get_bits(daddr->s6_addr, locator_bits,
					     v4_mask_len);
	*v4_da = htonl((u32)(da_field >> 32));

	*args_mob = seg6_mobile_addr_get_bits(daddr->s6_addr,
					      locator_bits + v4_mask_len,
					      SEG6_MOBILE_ARGS_MOB_LEN);
	return true;
}

/* Compose the IPv4 source address per RFC 9433 Section 6.6 Figure 10:
 * the @v4_mask_len high bits come from the inbound IPv6 SA at bit
 * offset @v6_src_prefix_len (or /64 when unset); the remaining low
 * bits come from @src_template at the same offset.
 */
static __be32 seg6_mobile_v4_sa(const struct in6_addr *ip6_sa,
				const struct in6_addr *src_template,
				u8 v4_mask_len, u8 v6_src_prefix_len)
{
	u8 p_bits = v6_src_prefix_len ? : SEG6_MOBILE_V6_SRC_PREFIX_LEN_DEFAULT;
	u8 sa_bits = min_t(u8, v4_mask_len, 32);
	u64 template_field, sa_field, mask;

	if ((unsigned int)p_bits + 32 > 128)
		return 0;

	template_field = seg6_mobile_addr_get_bits(src_template->s6_addr,
						   p_bits, 32);

	if (sa_bits) {
		sa_field = seg6_mobile_addr_get_bits(ip6_sa->s6_addr,
						     p_bits, sa_bits);
		mask = (sa_bits >= 64) ? ~0ULL : ((~0ULL) << (64 - sa_bits));
		template_field = (template_field & ~mask) | (sa_field & mask);
	}

	return htonl((u32)(template_field >> 32));
}

/* Return the bit length of the routing prefix that delivered @skb to
 * the current handler (i.e. the matched FIB entry's prefix length).
 * This is the locator length used to position v4DA / Args.Mob.Session
 * inside the SID per RFC 9433 Section 6.6.
 */
static unsigned int seg6_mobile_skb_prefix_bits(const struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct fib6_info *fib6;
	struct rt6_info *rt;
	u8 plen = 128;

	if (!dst || dst->ops->family != AF_INET6)
		return 128;

	rt = container_of(dst, struct rt6_info, dst);
	rcu_read_lock();
	fib6 = rcu_dereference(rt->from);
	if (fib6)
		plen = fib6->fib6_dst.plen;
	rcu_read_unlock();

	return plen;
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
 * PDU Session extension header (3GPP TS 38.415); @pdu_type selects
 * the PDU Type field (0 for downlink, 1 for uplink, 2..15 reserved).
 * When @pdu_type_set is false the GTPv1 short header is emitted with
 * no PDU Session Container, regardless of @qfi.
 */
static int seg6_mobile_push_gtpu(struct sk_buff *skb, u32 teid, u8 qfi,
				 u8 pdu_type, bool pdu_type_set)
{
	struct seg6_mobile_pdu_session_ext *pdu_session;
	struct gtp1_header_long *gtphl;
	struct gtp1_header *gtph;

	if (!pdu_type_set) {
		if (skb_cow_head(skb, sizeof(*gtph)))
			return -ENOMEM;

		gtph = (struct gtp1_header *)skb_push(skb, sizeof(*gtph));
		gtph->flags = SEG6_MOBILE_GTP1U_FLAGS_BASE;
		gtph->type = GTP_TPDU;
		gtph->length = htons(skb->len - sizeof(*gtph));
		gtph->tid = htonl(teid);
		return 0;
	}

	if (skb_cow_head(skb, sizeof(*gtphl) + sizeof(*pdu_session)))
		return -ENOMEM;

	pdu_session = skb_push(skb, sizeof(*pdu_session));
	pdu_session->ext_len = 1;
	pdu_session->pdu_type_spare = (pdu_type & 0xf) << 4;
	pdu_session->spare_qfi = qfi & SEG6_MOBILE_PDU_SESSION_QFI_MASK;
	pdu_session->next_ext = 0;

	gtphl = (struct gtp1_header_long *)skb_push(skb, sizeof(*gtphl));
	gtphl->flags = SEG6_MOBILE_GTP1U_FLAGS_BASE | GTP1_F_EXTHDR;
	gtphl->type = GTP_TPDU;
	gtphl->length = htons(skb->len - sizeof(struct gtp1_header));
	gtphl->tid = htonl(teid);
	gtphl->seq = 0;
	gtphl->npdu = 0;
	gtphl->next = SEG6_MOBILE_PDU_SESSION_NH;

	return 0;
}

/* Build the outer IPv4 + UDP + GTPv1-U[+PDU Session] header chain on
 * @skb and ship it via the IPv4 output path.  The IPv6 outer and its
 * extension headers must already have been popped.  IPv4 UDP
 * checksum is left zero (RFC 768 permits this for IPv4 outers; the
 * Linux GTP driver does the same in gtp_build_skb_ip4()).
 */
static int seg6_mobile_xmit_gtp4_e(struct net *net, struct sk_buff *skb,
				   struct seg6_mobile_lwt *slwt,
				   __be32 v4_sa, __be32 v4_da, u32 teid,
				   u8 qfi, u8 outer_tclass, u8 outer_hoplimit)
{
	struct flowi4 fl4;
	struct rtable *rt;
	struct udphdr *uh;
	struct iphdr *iph;

	if (skb_cow_head(skb,
			 sizeof(*iph) + sizeof(*uh) +
			 sizeof(struct gtp1_header_long) +
			 sizeof(struct seg6_mobile_pdu_session_ext)))
		return -ENOMEM;

	if (seg6_mobile_push_gtpu(skb, teid, qfi, slwt->pdu_type,
				  slwt->pdu_type_set))
		return -ENOMEM;

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

	/* The IPv4 source is synthesised from the IPv6 SA and the
	 * configured template, so a reverse route is not guaranteed.
	 * Use an output route lookup with FLOWI_FLAG_ANYSRC followed by
	 * dst_output(): the packet is treated as locally originated and
	 * traverses NF_INET_LOCAL_OUT from the IPv4 stack's perspective.
	 */
	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = v4_da;
	fl4.saddr = v4_sa;
	fl4.flowi4_proto = IPPROTO_UDP;
	fl4.flowi4_flags = FLOWI_FLAG_ANYSRC;

	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return PTR_ERR(rt);
	skb_dst_set(skb, &rt->dst);
	return dst_output(net, NULL, skb);
}

/* RFC 9433 Section 6.6 -- End.M.GTP4.E.  Receives an SRv6 packet whose
 * IPv6 destination encodes an IPv4 DA + 40-bit Args.Mob.Session, and
 * re-encapsulates the popped inner T-PDU in IPv4/UDP/GTP-U (with an
 * optional PDU Session extension header) toward a legacy IPv4
 * receiver.  RFC 6040 outer-to-outer propagation copies DSCP/ECN from
 * the IPv6 traffic class to the IPv4 ToS and Hop Limit to TTL.
 */
static int input_action_end_m_gtp4_e(struct sk_buff *skb,
				     struct seg6_mobile_lwt *slwt)
{
	enum seg6_mobile_srh_state srh_state;
	struct net *net = dev_net(skb->dev);
	unsigned int outer_len, ovhd;
	struct in6_addr ip6_sa;
	struct ipv6_sr_hdr *srh;
	struct ipv6hdr *ip6h;
	__be32 v4_da, v4_sa;
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

	if (!seg6_mobile_parse_gtp4_sid(&ip6h->daddr,
					seg6_mobile_skb_prefix_bits(skb),
					slwt->v4_mask_len,
					&v4_da, &args_mob))
		goto drop;

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
	v4_sa = seg6_mobile_v4_sa(&ip6_sa, &slwt->src_addr, slwt->v4_mask_len,
				  slwt->v6_src_prefix_len);

	/* RFC 9433 Section 6.6 S02: "Pop the IPv6 header and all its
	 * extension headers"; ipv6_skip_exthdr() walks HBH / Routing /
	 * Dest-Opts / Fragment in addition to the SRH.
	 */
	nh = ip6h->nexthdr;
	off = ipv6_skip_exthdr(skb, sizeof(*ip6h), &nh, &frag_off);
	if (off < 0)
		goto drop;
	outer_len = off;

	/* Reject GSO packets that would not fit the egress IPv4 path
	 * after adding the outer headers; the GSO segmenter cannot fix
	 * this up once the network protocol changes from IPv6 to IPv4.
	 */
	if (skb_is_gso(skb)) {
		unsigned int mtu = dst_mtu(skb_dst(skb));

		ovhd = sizeof(struct iphdr) + sizeof(struct udphdr) +
		       sizeof(struct gtp1_header_long) +
		       sizeof(struct seg6_mobile_pdu_session_ext);
		if (mtu && (mtu <= ovhd ||
			    !skb_gso_validate_network_len(skb, mtu - ovhd)))
			goto drop;
	}

	skb_pull_rcsum(skb, outer_len);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	if (seg6_mobile_xmit_gtp4_e(net, skb, slwt, v4_sa, v4_da, teid, qfi,
				    outer_tclass, outer_hoplimit))
		return -EINVAL;
	return 0;

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* Cross-attribute sanity check for actions that synthesise an IPv4
 * source from the IPv6 source per RFC 9433 Section 6.6 Figure 10: the
 * Source UPF Prefix length P (= the configured v6_src_prefix_len, or
 * SEG6_MOBILE_V6_SRC_PREFIX_LEN_DEFAULT when unset) must leave room
 * for the 32-bit IPv4 source template.
 */
static int seg6_mobile_v4_validate(struct seg6_mobile_lwt *slwt,
				   struct netlink_ext_ack *extack)
{
	u8 p_bits = slwt->v6_src_prefix_len ? :
		    SEG6_MOBILE_V6_SRC_PREFIX_LEN_DEFAULT;

	if ((unsigned int)p_bits + 32 > 128) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile v6_src_prefix_len must leave room for the 32-bit IPv4 source template (prefix_len <= 96)");
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

static int parse_nla_v4_mask_len(struct nlattr **attrs,
				 struct seg6_mobile_lwt *slwt,
				 struct netlink_ext_ack *extack)
{
	u8 len = nla_get_u8(attrs[SEG6_MOBILE_V4_MASK_LEN]);

	if (!seg6_mobile_v4_mask_valid(len)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile IPv4 mask length must be in 1..32");
		return -EINVAL;
	}
	slwt->v4_mask_len = len;
	return 0;
}

static int put_nla_v4_mask_len(struct sk_buff *skb,
			       struct seg6_mobile_lwt *slwt)
{
	if (nla_put_u8(skb, SEG6_MOBILE_V4_MASK_LEN, slwt->v4_mask_len))
		return -EMSGSIZE;
	return 0;
}

static int cmp_nla_v4_mask_len(struct seg6_mobile_lwt *a,
			       struct seg6_mobile_lwt *b)
{
	return a->v4_mask_len != b->v4_mask_len;
}

static int parse_nla_pdu_type(struct nlattr **attrs,
			      struct seg6_mobile_lwt *slwt,
			      struct netlink_ext_ack *extack)
{
	u8 t = nla_get_u8(attrs[SEG6_MOBILE_PDU_TYPE]);

	/* 3GPP TS 38.415: PDU Type is a 4-bit field. */
	if (t > 0xf) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile PDU Type must fit in 4 bits (0..15)");
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

	if (!tb[SEG6_MOBILE_CNT_PACKETS] || !tb[SEG6_MOBILE_CNT_BYTES] ||
	    !tb[SEG6_MOBILE_CNT_ERRORS])
		return -EINVAL;

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
		.attrs		= SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRC_ADDR) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_V4_MASK_LEN),
		.optattrs	= SEG6_F_MOBILE_COUNTERS |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_PDU_TYPE) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_V6_SRC_PREFIX_LEN),
		.input		= input_action_end_m_gtp4_e,
		.validate	= seg6_mobile_v4_validate,
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
	[SEG6_MOBILE_V4_MASK_LEN] = {
		.parse	= parse_nla_v4_mask_len,
		.put	= put_nla_v4_mask_len,
		.cmp	= cmp_nla_v4_mask_len,
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
};

static const struct nla_policy
seg6_mobile_policy[SEG6_MOBILE_MAX + 1] = {
	[SEG6_MOBILE_ACTION]		= { .type = NLA_U32 },
	[SEG6_MOBILE_NH6]		= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[SEG6_MOBILE_COUNTERS]		= { .type = NLA_NESTED },
	[SEG6_MOBILE_SRC_ADDR]		= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[SEG6_MOBILE_V4_MASK_LEN]	= { .type = NLA_U8 },
	[SEG6_MOBILE_PDU_TYPE]		= { .type = NLA_U8 },
	[SEG6_MOBILE_V6_SRC_PREFIX_LEN]	= { .type = NLA_U8 },
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

static void __destroy_attrs(unsigned long parsed_attrs,
			    struct seg6_mobile_lwt *slwt)
{
	const struct seg6_mobile_action_param *param;
	int i;

	for (i = SEG6_MOBILE_ACTION + 1; i <= SEG6_MOBILE_MAX; i++) {
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

	__destroy_attrs(attrs, slwt);
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
	__destroy_attrs(desc->attrs | parsed_optattrs, slwt);
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

	if (attrs & SEG6_MOBILE_F_ATTR(SEG6_MOBILE_V4_MASK_LEN))
		nlsize += nla_total_size(sizeof(u8));

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
