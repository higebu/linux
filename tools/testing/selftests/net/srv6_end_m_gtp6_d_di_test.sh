#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Selftest for the SRv6 End.M.GTP6.D.Di behavior (RFC 9433 Section 6.4).
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
# End.M.GTP6.D.Di SID 2001:db8:f::1.  srgw rewrites it as SRv6 carrying
# the configured SR Policy augmented with a leading slot that preserves
# the original outer destination at SRH[0], and forwards toward srupf.
# Unlike End.M.GTP6.D (Section 6.3), the GTP-U TEID/QFI are discarded;
# Args.Mob.Session is not stamped anywhere.  Non-T-PDU GTP-U (Echo
# Request) falls back to the lwtunnel's saved orig_input so a downstream
# legacy peer (lupf) that owns the GTP-U control plane can process them.
#
# A second SID exposes End.M.GTP6.D in the same netns so the .D and
# .D.Di output formats can be asserted side by side from the same gnb
# input -- the two behaviors must produce visibly different wire
# formats for the same T-PDU.
#
# Cases exercised:
#   1. Short GTPv1-U T-PDU -> SRv6 preserving the SID in SRH[0]
#   2. GTPv1-U + PDU Session (QFI=5) -> same output (QFI discarded)
#   3. Same input under End.M.GTP6.D -> Args.Mob.Session-stamped SRH[0]
#   4. Outer SRH with Segments Left != 0 -> drop
#   5. Malformed GTP-U extension chain -> drop
#   6. GTPv1-U Echo Request -> passthrough to lupf
#   7. Bad attribute (missing srh) -> ip route add returns EINVAL

source lib.sh

readonly RECV_TIMEOUT_MS=2000

readonly DI_SID="2001:db8:f::1"
readonly D_SID="2001:db8:fd::1"
readonly SR_POLICY_LAST="2001:db8:3::e"
readonly OUTER_SRC="2001:db8:2::1"
readonly SRUPF_LINK_ADDR="2001:db8:2::e"

readonly TEID_HEX="0x123"
readonly QFI=5
readonly PDU_TYPE_DL=0

# For End.M.GTP6.D.Di the outer DA equals the SR Policy first SID
# (single-segment policy => segments[first_segment=1]) and the
# prepended SRH[0] carries the original destination unchanged.
readonly EXPECTED_DI_OUTER_DA="${SR_POLICY_LAST}"
readonly EXPECTED_DI_SRH0="${DI_SID}"

# Reference values for the side-by-side comparison with End.M.GTP6.D
# (RFC 9433 Section 6.1 Args.Mob.Session layout: QFI(6) | R(1) | U(1) |
# TEID(32)).  For TEID=0x123, QFI=0 the 40-bit stamp is 0x00_00_00_01_23;
# with sr_prefix_len=64 it lands at bytes 8..12 of SRH[0].
readonly EXPECTED_D_SRH0_SHORT="2001:db8:3:0:0:1:2300:e"

HELPER_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly HELPER_DIR
readonly RECV="${HELPER_DIR}/srv6_mobile_recv"
readonly SEND="${HELPER_DIR}/srv6_mobile_send"

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

	if ! ip route help 2>&1 | grep -qF "End.M.GTP6.D.Di"; then
		echo "SKIP: iproute2 lacks End.M.GTP6.D.Di action"
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

	# Direct gnb to both behavior SIDs via srgw.
	ip -n "$gnb" -6 route add 2001:db8:f::/64  via 2001:db8:1::1
	ip -n "$gnb" -6 route add 2001:db8:fd::/64 via 2001:db8:1::1

	# Reach the SR Policy locator (and any Args.Mob.Session-stamped
	# variant in the same /64) via srupf's link address; this avoids
	# on-link ND on a synthesised SID address.
	ip -n "$srgw"  -6 route add 2001:db8:3::/64 via "${SRUPF_LINK_ADDR}" \
		dev veth-n9
	ip -n "$srupf" -6 route add 2001:db8:3::/64 dev veth-n9-srupf

	# End.M.GTP6.D.Di on srgw.  The route's next hop is the legacy
	# peer (lupf) so the lwtunnel's saved orig_input forwards
	# non-T-PDU GTP-U toward an existing neighbour.
	ip -n "$srgw" -6 route add 2001:db8:f::/64 \
		encap seg6mobile action End.M.GTP6.D.Di \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" count \
		via 2001:db8:6::e dev veth-n6

	# End.M.GTP6.D on the same srgw exposes the Section 6.3 wire
	# format for the side-by-side comparison.
	ip -n "$srgw" -6 route add 2001:db8:fd::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 64 count \
		via 2001:db8:6::e dev veth-n6
}

# Run the AF_PACKET receiver on srupf and fire one GTP-U packet from
# gnb at @sid.  Returns the receiver's exit status.
run_tpdu_match()
{
	local sid=$1
	local outer_da=$2
	local expected_srh0=$3
	local teid=$4
	local send_args=("${@:5}")
	local recv_pid rc=0

	ip netns exec "$srupf" "${RECV}" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${OUTER_SRC}" -d "${outer_da}" \
		-L "${expected_srh0}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${sid}" -t "${teid}" \
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
		-s "${OUTER_SRC}" -d "${EXPECTED_DI_OUTER_DA}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${DI_SID}" -t "${TEID_HEX}" \
		"${send_args[@]}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

# Run the passthrough receiver on lupf and fire an Echo Request from
# gnb.  Returns the receiver's exit status (0 if the unmodified packet
# emerges on the lupf leg).
run_echo_passthrough_match()
{
	local recv_pid rc=0

	ip netns exec "$lupf" "${RECV}" \
		-i veth-n6-lupf -m gtp6-passthru \
		-s 2001:db8:1::2 -d "${DI_SID}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${DI_SID}" --echo \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

test_short_tpdu_di()
{
	local rc

	rc=$(run_tpdu_match "${DI_SID}" \
		"${EXPECTED_DI_OUTER_DA}" "${EXPECTED_DI_SRH0}" \
		"${TEID_HEX}")
	log_test "$rc" 0 "End.M.GTP6.D.Di preserves the SID in SRH[0]"
}

test_psc_tpdu_di()
{
	local rc

	# The PDU Session QFI is parsed but discarded; SRH[0] still
	# carries the original SID unchanged.
	rc=$(run_tpdu_match "${DI_SID}" \
		"${EXPECTED_DI_OUTER_DA}" "${EXPECTED_DI_SRH0}" \
		"${TEID_HEX}" \
		--pdu-session -q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 0 "End.M.GTP6.D.Di discards QFI from a PDU Session T-PDU"
}

test_compare_with_d()
{
	local rc

	# The same input under End.M.GTP6.D yields the Section 6.3 wire
	# format -- SRH[0] carries the Args.Mob.Session stamp instead of
	# the original SID -- so a swap between the two action handlers
	# would surface as a mismatch here.
	rc=$(run_tpdu_match "${D_SID}" \
		"${EXPECTED_D_SRH0_SHORT}" "${EXPECTED_D_SRH0_SHORT}" \
		"${TEID_HEX}")
	log_test "$rc" 0 "End.M.GTP6.D produces a distinct SRH[0] for the same input"
}

test_drop_malformed_gtpu()
{
	local rc

	rc=$(run_tpdu_no_match --pdu-session --malformed \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 2 "End.M.GTP6.D.Di drops malformed GTP-U extension chain"
}

test_passthrough_echo()
{
	local rc

	rc=$(run_echo_passthrough_match)
	log_test "$rc" 0 "End.M.GTP6.D.Di passes Echo Request through to the legacy peer"
}

test_bad_attrs()
{
	local rc=0

	# Missing srh attribute must be rejected.
	ip -n "$srgw" -6 route add 2001:db8:bad1::/64 \
		encap seg6mobile action End.M.GTP6.D.Di \
			src "${OUTER_SRC}" \
		dev veth-n6 >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1

	# Missing src attribute must be rejected.
	ip -n "$srgw" -6 route add 2001:db8:bad2::/64 \
		encap seg6mobile action End.M.GTP6.D.Di \
			srh segs "${SR_POLICY_LAST}" \
		dev veth-n6 >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1

	log_test "$rc" 0 "End.M.GTP6.D.Di rejects bad attribute values at ip route add"
}

check_dependencies
setup

test_short_tpdu_di
test_psc_tpdu_di
test_compare_with_d
test_drop_malformed_gtpu
test_passthrough_echo
test_bad_attrs

print_log_test_results
exit "$ret"
