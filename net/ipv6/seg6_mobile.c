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
#include <net/l3mdev.h>
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
	/* Address family of the FIB hook the route is installed on.
	 * Defaults to AF_INET6 when 0; entries that run on IPv4 routes
	 * (currently only H.M.GTP4.D) set this to AF_INET explicitly.
	 */
	int input_family;
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
	struct ipv6_sr_hdr *srh;
	/* augmented SR Policy SRH used by End.M.GTP6.D.Di; its extra
	 * leading slot is stamped per-packet with the original outer DA.
	 */
	struct ipv6_sr_hdr *aug_srh;
	struct in6_addr nh6;
	struct in6_addr src_addr;
	u8 pdu_type;
	bool pdu_type_set;
	u8 v6_src_prefix_len;
	u8 sr_prefix_len;
	u32 vrftable;
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
 * skb_dst_drop() is needed before the call.  When the action carries
 * a configured vrftable, the egress FIB lookup is steered into that
 * table; otherwise the lookup inherits the receiving netns' main
 * resolution path.
 */
static int seg6_mobile_forward(struct sk_buff *skb,
			       struct seg6_mobile_lwt *slwt)
{
	seg6_lookup_nexthop(skb, NULL, slwt->vrftable);
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

	return seg6_mobile_forward(skb, slwt);

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

/* Write @nbits (top bits of @val) into a 16-byte big-endian @addr at
 * bit offset @bit_off, preserving the surrounding bits.  Caller
 * ensures bit_off + nbits <= 128 and 1 <= nbits <= 64.
 */
static void seg6_mobile_addr_set_bits(u8 *addr, unsigned int bit_off,
				      unsigned int nbits, u64 val)
{
	u64 hi = get_unaligned_be64(addr);
	u64 lo = get_unaligned_be64(addr + 8);
	u64 mask_hi, mask_lo;

	val &= GENMASK_ULL(63, 64 - nbits);

	if (bit_off >= 64) {
		mask_lo = GENMASK_ULL(63, 64 - nbits) >> (bit_off - 64);
		lo = (lo & ~mask_lo) | (val >> (bit_off - 64));
	} else if (bit_off + nbits <= 64) {
		mask_hi = GENMASK_ULL(63, 64 - nbits) >> bit_off;
		hi = (hi & ~mask_hi) | (val >> bit_off);
	} else {
		unsigned int hi_bits = 64 - bit_off;

		mask_hi = GENMASK_ULL(hi_bits - 1, 0);
		mask_lo = GENMASK_ULL(63, 64 - (nbits - hi_bits));
		hi = (hi & ~mask_hi) | (val >> bit_off);
		lo = (lo & ~mask_lo) | ((val << hi_bits) & mask_lo);
	}

	put_unaligned_be64(hi, addr);
	put_unaligned_be64(lo, addr + 8);
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

/* Combine TEID and QFI into a left-justified Args.Mob.Session value;
 * R/U are emitted as zero.
 */
static u64 seg6_mobile_args_from_teid_qfi(u32 teid, u8 qfi)
{
	return ((u64)(qfi & SEG6_MOBILE_PDU_SESSION_QFI_MASK) <<
		 SEG6_MOBILE_ARGS_QFI_SHIFT) |
	       ((u64)teid << SEG6_MOBILE_ARGS_TEID_SHIFT);
}

/* Stamp the 40-bit Args.Mob.Session into @addr at bit offset
 * @prefix_bits, the locator length of the SID into which the
 * argument space is written.  Caller validates that prefix_bits +
 * SEG6_MOBILE_ARGS_MOB_LEN <= 128.
 */
static void seg6_mobile_write_args_mob(struct in6_addr *addr,
				       unsigned int prefix_bits, u64 args_mob)
{
	seg6_mobile_addr_set_bits(addr->s6_addr, prefix_bits,
				  SEG6_MOBILE_ARGS_MOB_LEN, args_mob);
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

/* Parse the GTP-U header at @gtp_off, pulling each additional region
 * (long header, extension chain) into the linear area as it walks.
 *
 * Returns the GTP-U envelope length on success (with @teid / @qfi
 * filled in when non-NULL; @qfi is 0 if no PDU Session extension is
 * present), -EOPNOTSUPP for non-T-PDU messages the caller should
 * forward to downstream control-plane handling, or -EINVAL for
 * malformed input.
 *
 * Callers must re-derive any pointers into @skb->data afterwards:
 * pskb_may_pull() may have reallocated skb->head.
 */
static int seg6_mobile_parse_gtpu(struct sk_buff *skb, unsigned int gtp_off,
				  u32 *teid, u8 *qfi)
{
	const struct gtp1_header_long *gtphl;
	const struct gtp1_header *gtph;
	bool pdu_session_seen = false;
	unsigned int hdrlen;
	u8 flags, next;

	if (!pskb_may_pull(skb, gtp_off + sizeof(*gtph)))
		return -EINVAL;
	gtph = (const struct gtp1_header *)(skb->data + gtp_off);
	flags = gtph->flags;

	/* Accept only GTPv1-U; reject any other GTP version or protocol
	 * type via the flags mask.
	 */
	if ((flags & ~GTP1_F_MASK) != SEG6_MOBILE_GTP1U_FLAGS_BASE)
		return -EOPNOTSUPP;
	if (gtph->type != GTP_TPDU)
		return -EOPNOTSUPP;

	if (teid)
		*teid = ntohl(gtph->tid);
	if (qfi)
		*qfi = 0;

	if (!(flags & (GTP1_F_EXTHDR | GTP1_F_SEQ | GTP1_F_NPDU)))
		return sizeof(*gtph);

	if (!pskb_may_pull(skb, gtp_off + sizeof(*gtphl)))
		return -EINVAL;
	hdrlen = sizeof(*gtphl);

	if (!(flags & GTP1_F_EXTHDR))
		return hdrlen;

	gtphl = (const struct gtp1_header_long *)(skb->data + gtp_off);
	next = gtphl->next;
	while (next != 0) {
		unsigned int ext_len;
		const u8 *ext_hdr;

		if (!pskb_may_pull(skb, gtp_off + hdrlen + 1))
			return -EINVAL;
		ext_hdr = skb->data + gtp_off + hdrlen;
		ext_len = ext_hdr[0] * 4;
		if (ext_len == 0)
			return -EINVAL;

		if (!pskb_may_pull(skb, gtp_off + hdrlen + ext_len))
			return -EINVAL;
		ext_hdr = skb->data + gtp_off + hdrlen;

		if (next == SEG6_MOBILE_PDU_SESSION_NH) {
			/* the PDU Session extension header is fixed 4
			 * bytes and a T-PDU carries at most one
			 */
			if (ext_len != 4 || pdu_session_seen)
				return -EINVAL;
			pdu_session_seen = true;
			if (qfi)
				*qfi = ext_hdr[2] &
				       SEG6_MOBILE_PDU_SESSION_QFI_MASK;
		}

		/* the last byte of an extension header holds the Next
		 * Extension Header Type of the one that follows
		 */
		next = ext_hdr[ext_len - 1];
		hdrlen += ext_len;
	}

	return hdrlen;
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
	struct net_device *dev = skb->dev;
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

	/* A configured vrftable steers the egress lookup into that table by
	 * routing as if the rebuilt packet ingressed on the bound VRF master
	 * device; otherwise the lookup keys off the SR-ingress device.  RFC
	 * 9433 End.M.GTP4.E only requires submitting the packet to the egress
	 * IPv4 FIB lookup, leaving the table choice to the operator.
	 */
	if (slwt->vrftable) {
		int vrf_ifindex;

		vrf_ifindex = l3mdev_ifindex_lookup_by_table_id(L3MDEV_TYPE_VRF,
								net,
								slwt->vrftable);
		if (vrf_ifindex < 0)
			goto drop;
		dev = dev_get_by_index_rcu(net, vrf_ifindex);
		if (!dev)
			goto drop;
	}

	/* Resolve the egress route on the input path and hand the packet
	 * to dst_input() so it traverses NF_INET_PRE_ROUTING and
	 * NF_INET_FORWARD like every other transformed MUP packet,
	 * keeping iptables/nftables FORWARD rules effective.  The IPv4
	 * source is synthesised from the IPv6 SA and has no reverse
	 * route, so operators must disable rp_filter on the ingress
	 * device (net.ipv4.conf.<dev>.rp_filter=0) for this behavior.
	 */
	reason = ip_route_input(skb, v4_da, v4_sa,
				inet_dsfield_to_dscp(outer_tclass), dev);
	if (reason) {
		kfree_skb_reason(skb, reason);
		return -EINVAL;
	}
	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
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
	 * rp_filter relaxation.  A configured vrftable steers the lookup
	 * into that table, matching the End.M.GTP6.D egress.
	 */
	if (slwt->vrftable)
		seg6_lookup_nexthop(skb, NULL, slwt->vrftable);
	else
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

/* Forward a packet through the lwtunnel's saved orig_input, which
 * lwtunnel_set_redirect() populated when this route was installed.
 * @skb is consumed.
 */
static int seg6_mobile_orig_input(struct sk_buff *skb)
{
	return skb_dst(skb)->lwtstate->orig_input(skb);
}

/* strip the outer IPv6 / UDP / GTPv1-U envelope so the inner T-PDU
 * lies at the network header; shared by End.M.GTP6.D / End.M.GTP6.D.Di.
 *
 * Returns 0 on success with @inner_proto and (when non-NULL) @teid /
 * @qfi filled in, -EOPNOTSUPP for non-T-PDU outers (caller falls
 * through to orig_input for downstream control-plane handling), or
 * -EINVAL for malformed packets the caller must drop.
 */
static int seg6_mobile_decap_gtp6_outer(struct sk_buff *skb, u32 *teid,
					u8 *qfi, int *inner_proto)
{
	enum seg6_mobile_srh_state srh_state;
	unsigned int outer_len, inner_hlen;
	struct ipv6_sr_hdr *srh;
	struct ipv6hdr *ip6h;
	__be16 inner_eth;
	struct udphdr *uh;
	__be16 frag_off;
	int gtp_hdrlen;
	int upper_off;
	u8 inner_ver;
	u8 nh;

	/* drop if the outer SRH carries SegmentsLeft != 0 */
	srh = seg6_mobile_get_and_validate_srh(skb, &srh_state);
	if (srh_state == SEG6_MOBILE_SRH_MALFORMED)
		return -EINVAL;
	if (srh && srh->segments_left != 0)
		return -EINVAL;

	if (!pskb_may_pull(skb, sizeof(*ip6h)))
		return -EINVAL;

	ip6h = ipv6_hdr(skb);
	nh = ip6h->nexthdr;
	upper_off = ipv6_skip_exthdr(skb, sizeof(*ip6h), &nh, &frag_off);
	if (upper_off < 0 || frag_off)
		return -EINVAL;
	if (nh != IPPROTO_UDP)
		return -EOPNOTSUPP;

	if (!pskb_may_pull(skb, upper_off + sizeof(*uh)))
		return -EINVAL;
	ip6h = ipv6_hdr(skb);
	uh = (struct udphdr *)((u8 *)ip6h + upper_off);
	if (uh->dest != htons(GTP1U_PORT))
		return -EOPNOTSUPP;

	gtp_hdrlen = seg6_mobile_parse_gtpu(skb, upper_off + sizeof(*uh),
					    teid, qfi);
	if (gtp_hdrlen == -EOPNOTSUPP)
		return -EOPNOTSUPP;
	if (gtp_hdrlen < 0)
		return -EINVAL;

	outer_len = upper_off + sizeof(*uh) + gtp_hdrlen;

	if (!pskb_may_pull(skb, outer_len + 1))
		return -EINVAL;

	/* for an IPv4v6 PDU Session Type the inner NH is identified by
	 * the first nibble of the inner PDU.
	 */
	inner_ver = *((u8 *)skb->data + outer_len) >> 4;
	switch (inner_ver) {
	case 4:
		*inner_proto = IPPROTO_IPIP;
		inner_eth = htons(ETH_P_IP);
		inner_hlen = sizeof(struct iphdr);
		break;
	case 6:
		*inner_proto = IPPROTO_IPV6;
		inner_eth = htons(ETH_P_IPV6);
		inner_hlen = sizeof(struct ipv6hdr);
		break;
	default:
		return -EINVAL;
	}

	if (!pskb_may_pull(skb, outer_len + inner_hlen))
		return -EINVAL;

	skb_pull_rcsum(skb, outer_len);
	skb_reset_network_header(skb);
	skb->protocol = inner_eth;
	skb_set_transport_header(skb, inner_hlen);

	return 0;
}

/* Push the SR Policy outer IPv6 + SRH in front of the decapsulated inner
 * T-PDU, shared by End.M.GTP6.D[.Di] and H.M.GTP4.D.  After encapsulation
 * a GSO inner T-PDU becomes an IP-in-IPv6 tunnel payload, so mark the skb
 * encapsulated and snapshot the inner headers; the segmentation engine
 * then re-segments it under the new outer header.  This mirrors the
 * generic SRv6 lwtunnel encap path (seg6_do_srh()).  A non-GSO T-PDU
 * needs none of this.
 *
 * On entry @skb->protocol and its network/transport headers point at the
 * inner T-PDU; on return @skb->protocol is ETH_P_IPV6.
 */
static int seg6_mobile_srh_reencap(struct sk_buff *skb,
				   struct ipv6_sr_hdr *srh, int inner_proto)
{
	__be16 inner_eth = skb->protocol;
	bool gso = skb_is_gso(skb);
	int err;

	if (gso) {
		err = iptunnel_handle_offloads(skb, SKB_GSO_IPXIP6);
		if (err)
			return err;
	}

	err = seg6_do_srh_encap(skb, srh, inner_proto);
	if (err)
		return err;

	if (gso) {
		skb_set_inner_transport_header(skb, skb_transport_offset(skb));
		skb_set_inner_protocol(skb, inner_eth);
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	}

	skb->protocol = htons(ETH_P_IPV6);
	return 0;
}

/* Write the 16-byte @new_addr into @field inside the packet, keeping
 * skb->csum valid for CHECKSUM_COMPLETE skbs.  Every per-packet field
 * stamped after seg6_mobile_srh_reencap() (which folded the pushed
 * outer headers into skb->csum via skb_postpush_rcsum()) must go
 * through this helper.
 */
static void seg6_mobile_set_addr(struct sk_buff *skb, struct in6_addr *field,
				 const struct in6_addr *new_addr)
{
	struct in6_addr old_addr = *field;

	*field = *new_addr;
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		update_csum_diff16(skb, old_addr.s6_addr32,
				   field->s6_addr32);
}

/* strip the outer GTP-U envelope and re-encap the inner T-PDU in SRv6 */
static int input_action_end_m_gtp6_d(struct sk_buff *skb,
				     struct seg6_mobile_lwt *slwt)
{
	struct ipv6_sr_hdr *new_srh;
	struct in6_addr seg0;
	int inner_proto;
	u64 args_mob;
	u32 teid;
	int err;
	u8 qfi;

	err = seg6_mobile_decap_gtp6_outer(skb, &teid, &qfi, &inner_proto);
	if (err == -EOPNOTSUPP)
		return seg6_mobile_orig_input(skb);
	if (err)
		goto drop;

	/* push a new IPv6 + SRH carrying the configured SR Policy;
	 * seg6_do_srh_encap sets the outer DA to segments[first_segment].
	 */
	if (seg6_mobile_srh_reencap(skb, slwt->srh, inner_proto))
		goto drop;

	new_srh = (struct ipv6_sr_hdr *)(skb_network_header(skb) +
					 sizeof(struct ipv6hdr));
	/* For a single-segment SR Policy first_segment == 0 and the
	 * freshly-stamped segments[0] is also the outer DA, so refresh
	 * it; for multi-segment policies the outer DA references a
	 * different segment and remains valid.
	 */
	args_mob = seg6_mobile_args_from_teid_qfi(teid, qfi);
	seg0 = new_srh->segments[0];
	seg6_mobile_write_args_mob(&seg0, slwt->sr_prefix_len, args_mob);
	seg6_mobile_set_addr(skb, &new_srh->segments[0], &seg0);
	seg6_mobile_set_addr(skb, &ipv6_hdr(skb)->daddr,
			     &new_srh->segments[new_srh->first_segment]);
	seg6_mobile_set_addr(skb, &ipv6_hdr(skb)->saddr, &slwt->src_addr);

	nf_reset_ct(skb);
	return seg6_mobile_forward(skb, slwt);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* allocate the augmented SR Policy SRH used by End.M.GTP6.D.Di; the
 * leading slot is stamped per-packet with the original outer DA.
 */
static int seg6_mobile_end_m_gtp6_d_di_validate(struct seg6_mobile_lwt *slwt,
						struct netlink_ext_ack *extack)
{
	struct ipv6_sr_hdr *aug;
	int orig_len, aug_len;

	/* hdrlen is u8 and counts the SRH length in 8-byte units minus
	 * one.  The augmented SRH adds one 16-byte segment, so reject
	 * inputs whose +2-unit hdrlen would not fit.
	 */
	if (slwt->srh->hdrlen > 253) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile SRH too large for End.M.GTP6.D.Di (max 126 segments)");
		return -EINVAL;
	}

	orig_len = (slwt->srh->hdrlen + 1) << 3;
	aug_len = orig_len + sizeof(struct in6_addr);

	aug = kzalloc(aug_len, GFP_KERNEL);
	if (!aug)
		return -ENOMEM;

	memcpy(aug, slwt->srh, sizeof(*aug));
	aug->hdrlen = (aug_len >> 3) - 1;
	aug->segments_left = slwt->srh->segments_left + 1;
	aug->first_segment = slwt->srh->first_segment + 1;
	/* segments[0] is left zero; the data path overwrites it with
	 * the original outer destination once seg6_do_srh_encap() has
	 * copied the SRH into the skb.
	 */
	memcpy(&aug->segments[1], &slwt->srh->segments[0],
	       orig_len - sizeof(*aug));

	slwt->aug_srh = aug;
	return 0;
}

/* drop-in variant of End.M.GTP6.D that preserves the original outer DA at SRH[0] */
static int input_action_end_m_gtp6_d_di(struct sk_buff *skb,
					struct seg6_mobile_lwt *slwt)
{
	struct ipv6_sr_hdr *new_srh;
	struct in6_addr orig_dst;
	int inner_proto;
	int err;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		goto drop;
	orig_dst = ipv6_hdr(skb)->daddr;

	/* TEID/QFI are not consumed by the drop-in variant; the SR
	 * domain sees no per-session marking from this hop.
	 */
	err = seg6_mobile_decap_gtp6_outer(skb, NULL, NULL, &inner_proto);
	if (err == -EOPNOTSUPP)
		return seg6_mobile_orig_input(skb);
	if (err)
		goto drop;

	if (seg6_mobile_srh_reencap(skb, slwt->aug_srh, inner_proto))
		goto drop;

	new_srh = (struct ipv6_sr_hdr *)(skb_network_header(skb) +
					 sizeof(struct ipv6hdr));
	/* preserve the original outer destination in the prepended slot
	 * so the SR domain still delivers to the pre-drop-in endpoint.
	 */
	seg6_mobile_set_addr(skb, &new_srh->segments[0], &orig_dst);
	seg6_mobile_set_addr(skb, &ipv6_hdr(skb)->saddr, &slwt->src_addr);

	nf_reset_ct(skb);
	return seg6_mobile_forward(skb, slwt);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* Overlay the 32-bit IPv4 source @v4 into the IPv6 source template
 * @addr at bit offset @v6_src_prefix_len (default /64), per RFC 9433.
 * The trailing "ignored" bits of @addr (the operator's configured
 * src_addr) are left untouched.  seg6_mobile_v4_validate() guarantees
 * the overlay fits in 128 bits at build time.
 */
static void seg6_mobile_overlay_v4(struct in6_addr *addr,
				   u8 v6_src_prefix_len, __be32 v4)
{
	u8 p_bits = v6_src_prefix_len ? : SEG6_MOBILE_V6_SRC_PREFIX_LEN_DEFAULT;

	seg6_mobile_addr_set_bits(addr->s6_addr, p_bits, 32,
				  (u64)ntohl(v4) << 32);
}

/* Encode the 32-bit IPv4 DA and 40-bit Args.Mob.Session into @sid
 * right after a @prefix_bits-bit locator (RFC 9433).
 * seg6_mobile_v4_validate() guarantees the three fields fit in 128
 * bits at build time.
 */
static void seg6_mobile_fill_egress_sid(struct in6_addr *sid,
					unsigned int prefix_bits,
					__be32 v4, u64 args)
{
	seg6_mobile_addr_set_bits(sid->s6_addr, prefix_bits, 32,
				  (u64)ntohl(v4) << 32);
	seg6_mobile_addr_set_bits(sid->s6_addr, prefix_bits + 32,
				  SEG6_MOBILE_ARGS_MOB_LEN, args);
}

/* strip the inbound IPv4/UDP/GTP-U envelope and re-encap as SRv6 */
static int input_action_h_m_gtp4_d(struct sk_buff *skb,
				   struct seg6_mobile_lwt *slwt)
{
	unsigned int outer_len, inner_hlen, srh_len, post_encap, mtu;
	struct in6_addr new_da, new_sa;
	struct ipv6_sr_hdr *new_srh;
	int inner_proto, gtp_hdrlen;
	__be32 v4_da, v4_sa;
	struct iphdr *ip4h;
	struct udphdr *uh;
	u8 outer_tclass;
	__be16 inner_eth;
	__be32 old_flow;
	u64 args_mob;
	u8 inner_ver;
	u32 teid;
	int ihl;
	u8 qfi;

	if (!pskb_may_pull(skb, sizeof(*ip4h)))
		goto drop;

	ip4h = ip_hdr(skb);
	if (ip4h->protocol != IPPROTO_UDP || ip4h->ihl < 5)
		goto drop;

	ihl = ip4h->ihl * 4;
	if (!pskb_may_pull(skb, ihl + sizeof(*uh)))
		goto drop;

	ip4h = ip_hdr(skb);
	uh = (struct udphdr *)((u8 *)ip4h + ihl);
	if (uh->dest != htons(GTP1U_PORT))
		goto drop;

	/* Snapshot the outer IPv4 fields before seg6_mobile_parse_gtpu(),
	 * whose pskb_may_pull() calls may invalidate @ip4h.
	 */
	v4_da = ip4h->daddr;
	v4_sa = ip4h->saddr;
	outer_tclass = ipv4_get_dsfield(ip4h);

	gtp_hdrlen = seg6_mobile_parse_gtpu(skb, ihl + sizeof(*uh), &teid, &qfi);
	if (gtp_hdrlen == -EOPNOTSUPP)
		return seg6_mobile_orig_input(skb);
	if (gtp_hdrlen < 0)
		goto drop;

	args_mob = seg6_mobile_args_from_teid_qfi(teid, qfi);

	new_da = slwt->srh->segments[0];
	seg6_mobile_fill_egress_sid(&new_da, slwt->sr_prefix_len, v4_da,
				    args_mob);

	new_sa = slwt->src_addr;
	seg6_mobile_overlay_v4(&new_sa, slwt->v6_src_prefix_len, v4_sa);

	outer_len = ihl + sizeof(*uh) + gtp_hdrlen;
	if (!pskb_may_pull(skb, outer_len + 1))
		goto drop;

	inner_ver = *((u8 *)skb->data + outer_len) >> 4;
	switch (inner_ver) {
	case 4:
		inner_proto = IPPROTO_IPIP;
		inner_eth = htons(ETH_P_IP);
		inner_hlen = sizeof(struct iphdr);
		break;
	case 6:
		inner_proto = IPPROTO_IPV6;
		inner_eth = htons(ETH_P_IPV6);
		inner_hlen = sizeof(struct ipv6hdr);
		break;
	default:
		goto drop;
	}

	if (!pskb_may_pull(skb, outer_len + inner_hlen))
		goto drop;

	/* Reject a non-GSO packet that would not fit the post-encap MTU:
	 * IPv6 does not fragment in transit.  A GSO T-PDU is re-segmented
	 * under the new outer header by the segmentation engine (see
	 * seg6_mobile_srh_reencap()), so it needs no such check here.
	 */
	if (!skb_is_gso(skb)) {
		srh_len = (slwt->srh->hdrlen + 1) << 3;
		post_encap = skb->len - outer_len + sizeof(struct ipv6hdr) +
			     srh_len;
		mtu = dst_mtu(skb_dst(skb));
		if (mtu && post_encap > mtu)
			goto drop;
	}

	skb_pull_rcsum(skb, outer_len);
	skb_reset_network_header(skb);
	skb->protocol = inner_eth;
	skb_set_transport_header(skb, inner_hlen);

	if (seg6_mobile_srh_reencap(skb, slwt->srh, inner_proto))
		goto drop;

	new_srh = (struct ipv6_sr_hdr *)(skb_network_header(skb) +
					 sizeof(struct ipv6hdr));
	seg6_mobile_set_addr(skb, &new_srh->segments[0], &new_da);
	seg6_mobile_set_addr(skb, &ipv6_hdr(skb)->daddr,
			     &new_srh->segments[new_srh->first_segment]);
	seg6_mobile_set_addr(skb, &ipv6_hdr(skb)->saddr, &new_sa);

	/* Propagate the inbound IPv4 DSCP+ECN into the new outer IPv6
	 * Traffic Class; seg6_do_srh_encap() zeroes it for IPv4 inners.
	 */
	old_flow = *(__be32 *)ipv6_hdr(skb);
	ipv6_change_dsfield(ipv6_hdr(skb), 0, outer_tclass);
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		update_csum_diff4(skb, old_flow, *(__be32 *)ipv6_hdr(skb));

	nf_reset_ct(skb);
	return seg6_mobile_forward(skb, slwt);

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

static int parse_nla_srh(struct nlattr **attrs, struct seg6_mobile_lwt *slwt,
			 struct netlink_ext_ack *extack)
{
	struct ipv6_sr_hdr *srh;
	int len;

	srh = nla_data(attrs[SEG6_MOBILE_SRH]);
	len = nla_len(attrs[SEG6_MOBILE_SRH]);

	if (len < sizeof(*srh) + sizeof(struct in6_addr)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile SRH must contain at least one segment");
		return -EINVAL;
	}

	if (!seg6_validate_srh(srh, len, false)) {
		NL_SET_ERR_MSG_MOD(extack, "SRv6 Mobile SRH is malformed");
		return -EINVAL;
	}

	/* The D-side behaviors stamp per-packet fields (Args.Mob.Session
	 * or the original outer DA) into the SRH after seg6_do_srh_encap()
	 * has signed it, which would invalidate the HMAC.
	 */
	if (sr_has_hmac(srh)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile SRH must not carry an HMAC TLV");
		return -EINVAL;
	}

	slwt->srh = kmemdup(srh, len, GFP_KERNEL);
	if (!slwt->srh)
		return -ENOMEM;

	return 0;
}

static int put_nla_srh(struct sk_buff *skb, struct seg6_mobile_lwt *slwt)
{
	struct ipv6_sr_hdr *srh = slwt->srh;
	int len = (srh->hdrlen + 1) << 3;
	struct nlattr *nla;

	nla = nla_reserve(skb, SEG6_MOBILE_SRH, len);
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), srh, len);
	return 0;
}

static int cmp_nla_srh(struct seg6_mobile_lwt *a, struct seg6_mobile_lwt *b)
{
	int len = (a->srh->hdrlen + 1) << 3;

	if (len != ((b->srh->hdrlen + 1) << 3))
		return 1;

	return memcmp(a->srh, b->srh, len);
}

static void destroy_attr_srh(struct seg6_mobile_lwt *slwt)
{
	/* aug_srh is paired with srh: it is built from srh by the
	 * End.M.GTP6.D.Di validate hook and is NULL for every other
	 * action.
	 */
	kfree(slwt->aug_srh);
	kfree(slwt->srh);
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

static int parse_nla_vrftable(struct nlattr **attrs,
			      struct seg6_mobile_lwt *slwt,
			      struct netlink_ext_ack *extack)
{
	u32 table = nla_get_u32(attrs[SEG6_MOBILE_VRFTABLE]);

	if (table == 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile vrftable must be non-zero");
		return -EINVAL;
	}
	slwt->vrftable = table;
	return 0;
}

static int put_nla_vrftable(struct sk_buff *skb, struct seg6_mobile_lwt *slwt)
{
	if (nla_put_u32(skb, SEG6_MOBILE_VRFTABLE, slwt->vrftable))
		return -EMSGSIZE;
	return 0;
}

static int cmp_nla_vrftable(struct seg6_mobile_lwt *a,
			    struct seg6_mobile_lwt *b)
{
	return a->vrftable != b->vrftable;
}

/* The vrftable attribute steers the post-action egress FIB lookup into
 * a specific VRF table.  Mirror End.DT4's contract: require strict_mode
 * so the table-to-VRF binding is unambiguous, and require the table to
 * be bound to a VRF device so the resulting lookup behaves like an
 * intentional VRF crossing.
 */
static int seg6_mobile_check_vrftable(struct net *net,
				      struct seg6_mobile_lwt *slwt,
				      struct netlink_ext_ack *extack)
{
	int vrf_ifindex;

	vrf_ifindex = l3mdev_ifindex_lookup_by_table_id(L3MDEV_TYPE_VRF, net,
							slwt->vrftable);
	if (vrf_ifindex < 0) {
		if (vrf_ifindex == -EPERM)
			NL_SET_ERR_MSG_MOD(extack,
					   "Strict mode for VRF is disabled");
		else if (vrf_ifindex == -ENODEV)
			NL_SET_ERR_MSG_MOD(extack,
					   "Table has no associated VRF device");
		return vrf_ifindex;
	}
	return 0;
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
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_V6_SRC_PREFIX_LEN) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_VRFTABLE),
		.input		= input_action_end_m_gtp4_e,
		.validate	= seg6_mobile_end_m_gtp4_e_validate,
	},
	{
		.action		= SEG6_MOBILE_ACTION_END_M_GTP6_E,
		.attrs		= SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRC_ADDR) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SR_PREFIX_LEN),
		.optattrs	= SEG6_F_MOBILE_COUNTERS |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_PDU_TYPE) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_VRFTABLE),
		.input		= input_action_end_m_gtp6_e,
	},
	{
		.action		= SEG6_MOBILE_ACTION_END_M_GTP6_D,
		.attrs		= SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRC_ADDR) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRH) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SR_PREFIX_LEN),
		.optattrs	= SEG6_F_MOBILE_COUNTERS |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_VRFTABLE),
		.input		= input_action_end_m_gtp6_d,
	},
	{
		.action		= SEG6_MOBILE_ACTION_END_M_GTP6_D_DI,
		.attrs		= SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRC_ADDR) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRH),
		.optattrs	= SEG6_F_MOBILE_COUNTERS |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_VRFTABLE),
		.input		= input_action_end_m_gtp6_d_di,
		.validate	= seg6_mobile_end_m_gtp6_d_di_validate,
	},
	{
		.action		= SEG6_MOBILE_ACTION_H_M_GTP4_D,
		.input_family	= AF_INET,
		.attrs		= SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRC_ADDR) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRH) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SR_PREFIX_LEN),
		.optattrs	= SEG6_F_MOBILE_COUNTERS |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_V6_SRC_PREFIX_LEN) |
				  SEG6_MOBILE_F_ATTR(SEG6_MOBILE_VRFTABLE),
		.input		= input_action_h_m_gtp4_d,
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
	[SEG6_MOBILE_SRH] = {
		.parse		= parse_nla_srh,
		.put		= put_nla_srh,
		.cmp		= cmp_nla_srh,
		.destroy	= destroy_attr_srh,
	},
	[SEG6_MOBILE_SR_PREFIX_LEN] = {
		.parse	= parse_nla_sr_prefix_len,
		.put	= put_nla_sr_prefix_len,
		.cmp	= cmp_nla_sr_prefix_len,
	},
	[SEG6_MOBILE_VRFTABLE] = {
		.parse	= parse_nla_vrftable,
		.put	= put_nla_vrftable,
		.cmp	= cmp_nla_vrftable,
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
	[SEG6_MOBILE_SRH]		= { .type = NLA_BINARY },
	[SEG6_MOBILE_SR_PREFIX_LEN]	= { .type = NLA_U8 },
	[SEG6_MOBILE_VRFTABLE]		= { .type = NLA_U32 },
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
	int desc_family;
	bool family_ok;
	int rc;

	slwt = seg6_mobile_lwtunnel(orig_dst->lwtstate);
	desc_family = slwt->desc->input_family ? : AF_INET6;

	switch (skb->protocol) {
	case htons(ETH_P_IPV6):
		family_ok = desc_family == AF_INET6;
		break;
	case htons(ETH_P_IP):
		family_ok = desc_family == AF_INET;
		break;
	default:
		family_ok = false;
		break;
	}
	if (!family_ok) {
		kfree_skb(skb);
		return -EINVAL;
	}

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

	if (family != AF_INET6 && family != AF_INET)
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

	if ((desc->input_family ? : AF_INET6) != family) {
		NL_SET_ERR_MSG_MOD(extack,
				   "SRv6 Mobile action does not support this address family");
		return -EINVAL;
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

	if (slwt->vrftable) {
		err = seg6_mobile_check_vrftable(net, slwt, extack);
		if (err < 0) {
			destroy_attrs(slwt);
			kfree(newts);
			return err;
		}
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

	if (attrs & SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SRH))
		nlsize += nla_total_size((slwt->srh->hdrlen + 1) << 3);

	if (attrs & SEG6_MOBILE_F_ATTR(SEG6_MOBILE_SR_PREFIX_LEN))
		nlsize += nla_total_size(sizeof(u8));

	if (attrs & SEG6_MOBILE_F_ATTR(SEG6_MOBILE_VRFTABLE))
		nlsize += nla_total_size(sizeof(u32));

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
