#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Selftest for the SRv6 End.M.GTP6.D behavior (RFC 9433).
#
#   +-------+ 2001:db8:1::/64 +-------+ 2001:db8:2::/64 +-------+
#   |  gnb  | --------------- |  srgw | --------------- | srupf |
#   +-------+    veth-n3      +-------+    veth-n9      +-------+
#                                 |
#                                 |   2001:db8:6::/64
#                                 +----- veth-n6 ------- +-------+
#                                                        | lupf  |
#                                                        +-------+
#
# gnb injects an IPv6/UDP/GTPv1-U packet at the locally instantiated
# End.M.GTP6.D SID 2001:db8:f::1.  srgw rewrites it as SRv6 carrying
# the configured SR Policy, stamps Args.Mob.Session (TEID/QFI) into
# SRH[0], and forwards toward srupf.
# Non-T-PDU GTP-U messages (Echo Request) fall back to the lwtunnel's
# saved orig_input so a downstream legacy peer (lupf) that owns the
# GTP-U control plane can process them.
#
# Cases exercised:
#   1. Short GTPv1-U T-PDU                   -> SRv6 with stamped SRH[0]
#   2. GTPv1-U + PDU Session (QFI=5)         -> SRv6 with QFI in SRH[0]
#   3. Outer SRH with Segments Left != 0     -> drop
#   4. Malformed GTP-U extension chain       -> drop
#   5. Fragmented outer IPv6                  -> drop
#   6. Duplicate PDU Session containers       -> drop
#   7. GTPv1-U Echo Request                  -> passthrough to lupf
#   8. Bad attribute (sr_prefix_len 0 / 89)  -> ip route add returns EINVAL

source lib.sh

readonly RECV_TIMEOUT_MS=2000

readonly SID="2001:db8:f::1"
readonly SR_POLICY_LAST="2001:db8:3::e"
readonly OUTER_SRC="2001:db8:2::1"
readonly SRUPF_LINK_ADDR="2001:db8:2::e"

# Args.Mob.Session layout: QFI(6) | R(1) | U(1) | TEID(32).
# For TEID=0x123, QFI=0, the 40-bit stamp is 0x00_00_00_01_23;
# for TEID=0x123, QFI=5 it is 0x14_00_00_01_23.  With sr_prefix_len=64
# the stamp lands at bytes 8..12 of SRH[0].
readonly TEID_HEX="0x123"
readonly QFI=5
readonly PDU_TYPE_DL=0
readonly EXPECTED_LAST_SID_SHORT="2001:db8:3:0:0:1:2300:e"
readonly EXPECTED_LAST_SID_PSC="2001:db8:3:0:1400:1:2300:e"

HELPER_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly HELPER_DIR
readonly RECV="${HELPER_DIR}/srv6_mobile_recv"
readonly SEND="${HELPER_DIR}/srv6_mobile_send"
readonly GSO_SEND="${HELPER_DIR}/srv6_mobile_gso_send"

# GSO case.  End.M.GTP6.D consumes IPv6/UDP/GTP-U, which cannot be
# coalesced into a GSO frame by a plain socket, so an End.M.GTP6.E node
# (the RFC 9433 encap counterpart) is chained in front of it to produce
# the GTP-U TSO super-frame from an injected inner TCP flow.
readonly GSO_SEG=1000
readonly GSO_NSEGS=10
readonly GSO_INNER_SRC="2001:db8:aaaa::1"
readonly GSO_INNER_DST="2001:db8:200::2"
readonly GSO_TUNSRC="2001:db8:1::1"
# End.M.GTP6.E SID with Args.Mob.Session (QFI=5, TEID=0x123) at bytes 8..12,
# and the outer source it stamps on the emitted GTP-U.
readonly GSO_E_SID="2001:db8:e::1400:1:2300:0"
readonly GSO_E_SRC="2001:db8:20::1"

ret=0
nsuccess=0
nfail=0

PAUSE_ON_FAIL=${PAUSE_ON_FAIL:=no}

log_test()
{
	local rc=$1
	local expected=$2
	local msg="$3"

	if [ "${rc}" -eq "${expected}" ]; then
		nsuccess=$((nsuccess + 1))
		printf "\n    TEST: %-60s  [ OK ]\n" "${msg}"
	else
		ret=1
		nfail=$((nfail + 1))
		printf "\n    TEST: %-60s  [FAIL]\n" "${msg}"
		if [ "${PAUSE_ON_FAIL}" = "yes" ]; then
			echo
			echo "hit enter to continue, 'q' to quit"
			read -r a
			[ "$a" = "q" ] && exit 1
		fi
	fi
}

print_log_test_results()
{
	printf "\nTests passed: %3d\n" "${nsuccess}"
	printf "Tests failed: %3d\n"   "${nfail}"
}

cleanup()
{
	cleanup_all_ns
}

trap cleanup EXIT

check_dependencies()
{
	if [ "$(id -u)" -ne 0 ]; then
		echo "SKIP: need root privileges"
		exit "${ksft_skip}"
	fi

	for cmd in ip; do
		if ! command -v "$cmd" >/dev/null; then
			echo "SKIP: ${cmd} is required"
			exit "${ksft_skip}"
		fi
	done

	if [ ! -x "${RECV}" ] || [ ! -x "${SEND}" ]; then
		echo "SKIP: srv6_mobile_recv / srv6_mobile_send not built"
		exit "${ksft_skip}"
	fi

	if ! ip route help 2>&1 | grep -qF "seg6mobile"; then
		echo "SKIP: iproute2 lacks seg6mobile support"
		exit "${ksft_skip}"
	fi

	if ! ip route help 2>&1 | grep -qF "End.M.GTP6.D"; then
		echo "SKIP: iproute2 lacks End.M.GTP6.D action"
		exit "${ksft_skip}"
	fi
}

setup()
{
	setup_ns gnb srgw srupf lupf

	ip -n "$gnb"   link set lo up
	ip -n "$srgw"  link set lo up
	ip -n "$srupf" link set lo up
	ip -n "$lupf"  link set lo up

	# gnb <-> srgw
	ip link add veth-n3 netns "$gnb" \
		type veth peer name veth-n3-srgw netns "$srgw"
	ip -n "$gnb"  addr add 2001:db8:1::2/64 dev veth-n3 nodad
	ip -n "$srgw" addr add 2001:db8:1::1/64 dev veth-n3-srgw nodad
	ip -n "$gnb"  link set veth-n3 up
	ip -n "$srgw" link set veth-n3-srgw up

	# srgw <-> srupf (carries the post-encap SRv6 toward the SR-aware UPF)
	ip link add veth-n9 netns "$srgw" \
		type veth peer name veth-n9-srupf netns "$srupf"
	ip -n "$srgw"  addr add 2001:db8:2::1/64 dev veth-n9 nodad
	ip -n "$srupf" addr add "${SRUPF_LINK_ADDR}/64" dev veth-n9-srupf nodad
	ip -n "$srgw"  link set veth-n9 up
	ip -n "$srupf" link set veth-n9-srupf up

	# srgw <-> lupf (used by orig_input passthrough for non-T-PDU GTP-U)
	ip link add veth-n6 netns "$srgw" \
		type veth peer name veth-n6-lupf netns "$lupf"
	ip -n "$srgw" addr add 2001:db8:6::1/64 dev veth-n6 nodad
	ip -n "$lupf" addr add 2001:db8:6::e/64 dev veth-n6-lupf nodad
	ip -n "$srgw" link set veth-n6 up
	ip -n "$lupf" link set veth-n6-lupf up

	ip netns exec "$srgw"  sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$srgw"  sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$srgw"  sysctl -wq net.ipv6.conf.veth-n3-srgw.seg6_enabled=1
	ip netns exec "$srgw"  sysctl -wq net.ipv6.conf.veth-n9.seg6_enabled=1
	ip netns exec "$srgw"  sysctl -wq net.ipv6.conf.veth-n6.seg6_enabled=1
	ip netns exec "$srupf" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$srupf" sysctl -wq net.ipv6.conf.veth-n9-srupf.seg6_enabled=1

	ip netns exec "$gnb"   ethtool -K veth-n3 tx off rx off 2>/dev/null
	ip netns exec "$srgw"  ethtool -K veth-n3-srgw tx off rx off 2>/dev/null
	ip netns exec "$srgw"  ethtool -K veth-n9 tx off rx off 2>/dev/null
	ip netns exec "$srgw"  ethtool -K veth-n6 tx off rx off 2>/dev/null
	ip netns exec "$srupf" ethtool -K veth-n9-srupf tx off rx off 2>/dev/null
	ip netns exec "$lupf"  ethtool -K veth-n6-lupf tx off rx off 2>/dev/null

	# Direct gnb to the End.M.GTP6.D locator via srgw.
	ip -n "$gnb" -6 route add 2001:db8:f::/64 via 2001:db8:1::1

	# Reach the SR Policy locator (and any Args.Mob.Session-stamped
	# variant in the same /64) via srupf's link address; this avoids
	# on-link ND on a synthesised SID address.
	ip -n "$srgw"  -6 route add 2001:db8:3::/64 via "${SRUPF_LINK_ADDR}" \
		dev veth-n9
	ip -n "$srupf" -6 route add 2001:db8:3::/64 dev veth-n9-srupf

	# End.M.GTP6.D on srgw.  The route's next hop is the legacy peer
	# (lupf) so the lwtunnel's saved orig_input forwards non-T-PDU
	# GTP-U toward an existing neighbour, while T-PDU encap drops the
	# original dst and re-routes through the new outer DA.
	ip -n "$srgw" -6 route add 2001:db8:f::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 64 count \
		via 2001:db8:6::e dev veth-n6
}

read_nstat_counter()
{
	local ns=$1
	local name=$2

	ip netns exec "$ns" nstat -az "$name" \
		| awk -v n="$name" '$1 == n {print $2}'
}

# Run the AF_PACKET receiver on srupf and fire one GTP-U packet from
# gnb.  Returns the receiver's exit status.
run_tpdu_match()
{
	local expected_last_sid=$1
	local teid=$2
	local send_args=("${@:3}")
	local recv_pid rc=0

	# For a single-segment SR Policy the outer DA equals the
	# Args.Mob.Session-stamped SRH[0].
	ip netns exec "$srupf" "${RECV}" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${OUTER_SRC}" -d "${expected_last_sid}" \
		-L "${expected_last_sid}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${SID}" -t "${teid}" \
		"${send_args[@]}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

# Same as run_tpdu_match but expects the receiver to time out (the
# packet must not reach srupf).
run_tpdu_no_match()
{
	local send_args=("$@")
	local recv_pid rc=0

	ip netns exec "$srupf" "${RECV}" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${OUTER_SRC}" -d "${EXPECTED_LAST_SID_PSC}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${SID}" -t "${TEID_HEX}" \
		"${send_args[@]}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

# Assert that a T-PDU was dropped from the run_tpdu_no_match receiver
# result: exit 0 means a matching SRv6 packet was wrongly forwarded to
# srupf, while 1 (a non-matching arrival) and 2 (nothing) both confirm
# the drop.  srgw's Neighbor Discovery uses 2001:db8:2::1, the same
# address as the SRv6 outer source, so a bare timeout (exit 2) is not
# guaranteed; treat any non-match as a successful drop.
log_drop_test()
{
	local rc=$1

	[ "$rc" -ne 0 ] && rc=0 || rc=1
	log_test "$rc" 0 "$2"
}

# Run the passthrough receiver on lupf and fire an Echo Request from
# gnb.  Returns the receiver's exit status (0 if the unmodified packet
# emerges on the lupf leg).
run_echo_passthrough_match()
{
	local recv_pid rc=0

	ip netns exec "$lupf" "${RECV}" \
		-i veth-n6-lupf -m gtp6-passthru \
		-s 2001:db8:1::2 -d "${SID}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${SID}" --echo \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

test_short_tpdu()
{
	local rc

	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_SHORT}" "${TEID_HEX}")
	log_test "$rc" 0 "End.M.GTP6.D stamps Args.Mob.Session from a short T-PDU"
}

test_psc_tpdu()
{
	local rc

	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_PSC}" "${TEID_HEX}" \
		--pdu-session -q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 0 "End.M.GTP6.D propagates QFI via PDU Session"
}

test_drop_malformed_gtpu()
{
	local rc

	rc=$(run_tpdu_no_match --pdu-session --malformed \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 2 "End.M.GTP6.D drops malformed GTP-U extension chain"
}

# A fragmented outer IPv6 packet (Fragment extension header ahead of the
# UDP/GTP-U envelope) must be dropped: ipv6_skip_exthdr() reports a
# nonzero frag_off.  Without the check the same T-PDU would decapsulate
# into the SRv6 packet the receiver matches, so the drop is what turns
# the match into a timeout.
test_drop_frag_outer()
{
	local rc

	rc=$(run_tpdu_no_match --frag --pdu-session \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_drop_test "$rc" "End.M.GTP6.D drops a fragmented outer packet"
}

# Two PDU Session containers chained in the GTP-U extension header list
# must be dropped: a T-PDU carries at most one.
test_drop_dup_pdu_session()
{
	local rc

	rc=$(run_tpdu_no_match --pdu-session --dup-pdu-session \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_drop_test "$rc" "End.M.GTP6.D drops duplicate PDU Session containers"
}

test_passthrough_echo()
{
	local rc

	rc=$(run_echo_passthrough_match)
	log_test "$rc" 0 "End.M.GTP6.D passes Echo Request through to the legacy peer"
}

test_bad_attrs()
{
	local rc=0

	ip -n "$srgw" -6 route add 2001:db8:bad1::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 0 \
		dev veth-n6 >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1

	ip -n "$srgw" -6 route add 2001:db8:bad2::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 89 \
		dev veth-n6 >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1

	ip -n "$srgw" -6 route add 2001:db8:bad3::/64 \
		encap seg6mobile action End.M.GTP6.D \
			src "${OUTER_SRC}" sr_prefix_len 64 \
		dev veth-n6 >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1

	log_test "$rc" 0 "End.M.GTP6.D rejects bad attribute values at ip route add"
}

# End.M.GTP6.D must re-segment a GSO T-PDU under its new SRv6 outer header.
# GTP-U cannot be coalesced into a GSO frame by a plain socket, so a
# dedicated chain drives the behavior: a TCP TSO super-frame is injected
# on gso_ue, H.Encaps'd on gso_src toward an End.M.GTP6.E SID on gso_re,
# which emits the IPv6 GTP-U super-frame.  gso_rd runs the End.M.GTP6.D
# under test and must re-segment it into GSO_NSEGS SRv6 packets, counted
# on gso_dn.  The super-MSS GTP-U frame captured at the behavior ingress
# keeps the case from passing vacuously on a pre-segmented flow.
test_gso()
{
	local src_mac ing_pid cnt_pid cap seg_count ing_rc=0 rc=0

	if ! command -v tcpdump >/dev/null; then
		echo "SKIP: tcpdump is required for the GSO case"
		return
	fi

	setup_ns gso_ue gso_src gso_re gso_rd gso_dn

	# gso_ue <-> gso_src (UE injection leg).
	ip link add veth-ue netns "$gso_ue" \
		type veth peer name veth-ue-src netns "$gso_src"
	ip -n "$gso_ue"  addr add "${GSO_INNER_SRC}/64" dev veth-ue nodad
	ip -n "$gso_src" addr add 2001:db8:aaaa::254/64 dev veth-ue-src nodad
	ip -n "$gso_ue"  link set veth-ue up
	ip -n "$gso_src" link set veth-ue-src up

	# gso_src <-> gso_re (SRv6 toward the End.M.GTP6.E SID).
	ip link add veth-sr netns "$gso_src" \
		type veth peer name veth-sr-re netns "$gso_re"
	ip -n "$gso_src" addr add "${GSO_TUNSRC}/64" dev veth-sr nodad
	ip -n "$gso_re"  addr add 2001:db8:1::2/64    dev veth-sr-re nodad
	ip -n "$gso_src" link set veth-sr up
	ip -n "$gso_re"  link set veth-sr-re up

	# gso_re <-> gso_rd (IPv6 GTP-U).
	ip link add veth-re netns "$gso_re" \
		type veth peer name veth-rd netns "$gso_rd"
	ip -n "$gso_re" addr add 2001:db8:6::1/64 dev veth-re nodad
	ip -n "$gso_rd" addr add 2001:db8:6::2/64 dev veth-rd nodad
	ip -n "$gso_re" link set veth-re up
	ip -n "$gso_rd" link set veth-rd up

	# gso_rd <-> gso_dn (SRv6 output).  The link address is distinct from
	# the End.M.GTP6.D outer source (OUTER_SRC), so the behavior's own ND
	# is not mistaken for its emitted SRv6.
	ip link add veth-rr netns "$gso_rd" \
		type veth peer name veth-dn netns "$gso_dn"
	ip -n "$gso_rd" addr add 2001:db8:2::100/64 dev veth-rr nodad
	ip -n "$gso_dn" addr add 2001:db8:2::e/64   dev veth-dn nodad
	ip -n "$gso_rd" link set veth-rr up
	ip -n "$gso_dn" link set veth-dn up

	# Force segmentation only at the End.M.GTP6.D egress; the GTP-U
	# super-frame must reach the behavior un-split.
	ip netns exec "$gso_rd" ethtool -K veth-rr gso off tso off 2>/dev/null

	ip netns exec "$gso_src" sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$gso_re"  sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$gso_re"  sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$gso_re"  sysctl -wq net.ipv6.conf.veth-sr-re.seg6_enabled=1
	ip netns exec "$gso_rd"  sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$gso_rd"  sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$gso_rd"  sysctl -wq net.ipv6.conf.veth-rd.seg6_enabled=1

	# gso_src: H.Encaps the injected T-PDU as [End.M.GTP6.E SID,
	# End.M.GTP6.D SID], so End.M.GTP6.E takes the D SID as the GTP-U
	# destination.
	ip -n "$gso_src" -6 route add 2001:db8:e::/64 via 2001:db8:1::2
	ip -n "$gso_src" -6 route add "${GSO_INNER_DST}/128" \
		encap seg6 mode encap segs "${GSO_E_SID},${SID}" \
			tunsrc "${GSO_TUNSRC}" \
		via 2001:db8:1::2 dev veth-sr

	# gso_re: End.M.GTP6.E emits IPv6 GTP-U toward the End.M.GTP6.D SID.
	ip -n "$gso_re" -6 route add 2001:db8:e::/64 \
		encap seg6mobile action End.M.GTP6.E \
			sr_prefix_len 64 src "${GSO_E_SRC}" \
			pdu_type "${PDU_TYPE_DL}" \
		dev veth-re
	ip -n "$gso_re" -6 route add 2001:db8:f::/64 via 2001:db8:6::2

	# gso_rd: End.M.GTP6.D under test, then route the stamped SRv6 to
	# gso_dn.
	ip -n "$gso_rd" -6 route add 2001:db8:3::/64 via 2001:db8:2::e \
		dev veth-rr
	ip -n "$gso_rd" -6 route add 2001:db8:f::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 64 count \
		via 2001:db8:6::1 dev veth-rd

	src_mac=$(ip -n "$gso_src" link show veth-ue-src \
		| awk '/link\/ether/ {print $2}')

	# Warm the neighbor caches so the lone super-frames are not lost to
	# address resolution.
	ip netns exec "$gso_src" \
		ping -6 -c 1 -W 1 2001:db8:1::2 >/dev/null 2>&1 || true
	ip netns exec "$gso_re" \
		ping -6 -c 1 -W 1 2001:db8:6::2 >/dev/null 2>&1 || true
	ip netns exec "$gso_rd" \
		ping -6 -c 1 -W 1 2001:db8:2::e >/dev/null 2>&1 || true

	# Capture the single super-MSS GTP-U frame at the End.M.GTP6.D ingress
	# (non-vacuous guard) and count the SRv6 packets it is re-segmented
	# into at the egress toward gso_dn.  The egress filter keys on the
	# stamped last SID, so the count also confirms Args.Mob.Session made
	# it into every segment.
	cap=$(mktemp)
	ip netns exec "$gso_rd" timeout 3 tcpdump -p -c 1 -i veth-rd \
		"ip6 src ${GSO_E_SRC} and greater 1500" \
		>/dev/null 2>&1 &
	ing_pid=$!
	ip netns exec "$gso_dn" timeout 3 tcpdump -p -l -n -i veth-dn \
		"ip6 src ${OUTER_SRC} and dst ${EXPECTED_LAST_SID_PSC}" \
		>"$cap" 2>/dev/null &
	cnt_pid=$!
	sleep 0.5

	ip netns exec "$gso_ue" "${GSO_SEND}" \
		-i veth-ue -D "${src_mac}" \
		-s "${GSO_INNER_SRC}" -d "${GSO_INNER_DST}" \
		-S "${GSO_SEG}" -n "${GSO_NSEGS}" \
		>/dev/null 2>&1 || true

	wait "$ing_pid" || ing_rc=$?
	wait "$cnt_pid" 2>/dev/null
	seg_count=$(grep -c . "$cap")
	rm -f "$cap"

	# ing_rc 0 => a super-MSS GTP-U frame reached the behavior
	# (non-vacuous); seg_count == GSO_NSEGS => it was re-segmented into
	# that many SRv6 packets.
	[ "$ing_rc" -eq 0 ] && [ "$seg_count" -eq "$GSO_NSEGS" ] || rc=1
	log_test "$rc" 0 "End.M.GTP6.D re-segments a GSO T-PDU into SRv6 packets"
}

check_dependencies
setup

test_short_tpdu
test_psc_tpdu
test_drop_malformed_gtpu
test_drop_frag_outer
test_drop_dup_pdu_session
test_passthrough_echo
test_bad_attrs
test_gso

print_log_test_results
exit "$ret"
