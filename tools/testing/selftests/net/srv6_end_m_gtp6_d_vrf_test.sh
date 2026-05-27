#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Selftest for the SRv6 End.M.GTP6.D behavior with vrftable (RFC 9433).
#
# Same per-namespace shape as srv6_end_m_gtp6_d_test.sh, but on srgw the
# egress leg veth-n9 is enslaved into vrf-underlay (table 200) and the
# route to the SR Policy locator lives only in table 200.  The End.M.GTP6.D
# lwtunnel carries vrftable 200, so the post-action seg6_lookup_nexthop()
# runs in that table.  Removing the attribute leaves the lookup in the
# main table where no matching underlay route exists, proving the
# attribute is doing real work.

source lib.sh

readonly RECV_TIMEOUT_MS=2000

readonly SID="2001:db8:f::1"
readonly SR_POLICY_LAST="2001:db8:3::e"
readonly OUTER_SRC="2001:db8:2::1"
readonly SRUPF_LINK_ADDR="2001:db8:2::e"
readonly VRF_TABLE=200

readonly TEID_HEX="0x123"
readonly EXPECTED_LAST_SID_SHORT="2001:db8:3:0:0:1:2300:e"

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

	if ! ip route help 2>&1 | grep -qF "vrftable"; then
		echo "SKIP: iproute2 lacks vrftable keyword on seg6mobile"
		exit "${ksft_skip}"
	fi
}

setup()
{
	setup_ns gnb srgw srupf

	ip -n "$gnb"   link set lo up
	ip -n "$srgw"  link set lo up
	ip -n "$srupf" link set lo up

	ip link add veth-n3 netns "$gnb" \
		type veth peer name veth-n3-srgw netns "$srgw"
	ip -n "$gnb"  addr add 2001:db8:1::2/64 dev veth-n3 nodad
	ip -n "$srgw" addr add 2001:db8:1::1/64 dev veth-n3-srgw nodad
	ip -n "$gnb"  link set veth-n3 up
	ip -n "$srgw" link set veth-n3-srgw up

	ip netns exec "$srgw" sysctl -wq net.vrf.strict_mode=1
	ip -n "$srgw" link add vrf-underlay type vrf table "${VRF_TABLE}"
	ip -n "$srgw" link set vrf-underlay up

	# Enslave the egress leg BEFORE assigning its address so the
	# connected route lands in the VRF table.  Moving veth-n9 into the
	# VRF after the address has been added drops the IPv6 connected
	# route on the floor.
	ip link add veth-n9 netns "$srgw" \
		type veth peer name veth-n9-srupf netns "$srupf"
	ip -n "$srgw"  link set veth-n9 master vrf-underlay
	ip -n "$srgw"  addr add 2001:db8:2::1/64 dev veth-n9 nodad
	ip -n "$srupf" addr add "${SRUPF_LINK_ADDR}/64" dev veth-n9-srupf nodad
	ip -n "$srgw"  link set veth-n9 up
	ip -n "$srupf" link set veth-n9-srupf up

	ip netns exec "$srgw"  sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$srgw"  sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$srgw"  sysctl -wq net.ipv6.conf.veth-n3-srgw.seg6_enabled=1
	ip netns exec "$srgw"  sysctl -wq net.ipv6.conf.veth-n9.seg6_enabled=1
	ip netns exec "$srupf" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$srupf" sysctl -wq net.ipv6.conf.veth-n9-srupf.seg6_enabled=1

	ip netns exec "$srgw" ethtool -K veth-n3-srgw tx off rx off 2>/dev/null
	ip netns exec "$srgw" ethtool -K veth-n9 tx off rx off 2>/dev/null
	ip netns exec "$gnb"  ethtool -K veth-n3 tx off rx off 2>/dev/null
	ip netns exec "$srupf" ethtool -K veth-n9-srupf tx off rx off 2>/dev/null

	ip -n "$gnb" -6 route add 2001:db8:f::/64 via 2001:db8:1::1

	# The SR Policy locator route lives only in the underlay VRF; the
	# main table has no path to 2001:db8:3::/64.  This proves that the
	# post-action lookup must go through table ${VRF_TABLE}.
	ip -n "$srgw"  -6 route add table "${VRF_TABLE}" \
		2001:db8:3::/64 via "${SRUPF_LINK_ADDR}" dev veth-n9
	ip -n "$srupf" -6 route add 2001:db8:3::/64 dev veth-n9-srupf
}

run_tpdu_match()
{
	local recv_pid rc=0

	ip netns exec "$srupf" "${RECV}" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${OUTER_SRC}" -d "${EXPECTED_LAST_SID_SHORT}" \
		-L "${EXPECTED_LAST_SID_SHORT}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${SID}" -t "${TEID_HEX}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

test_vrftable_positive()
{
	local rc

	ip -n "$srgw" -6 route add "${SID}/128" \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 64 \
			vrftable "${VRF_TABLE}" \
		dev veth-n3-srgw

	rc=$(run_tpdu_match)
	log_test "$rc" 0 "End.M.GTP6.D with vrftable steers egress into the underlay VRF"

	ip -n "$srgw" -6 route del "${SID}/128"
}

test_vrftable_required()
{
	local rc

	# Same lwtunnel without vrftable: the post-action lookup falls
	# back to the main table which has no path to the SR Policy
	# locator, so the receiver must time out.
	ip -n "$srgw" -6 route add "${SID}/128" \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 64 \
		dev veth-n3-srgw

	rc=$(run_tpdu_match)
	log_test "$rc" 2 "End.M.GTP6.D without vrftable fails to reach the underlay"

	ip -n "$srgw" -6 route del "${SID}/128"
}

test_strict_mode_off()
{
	local rc=0

	ip netns exec "$srgw" sysctl -wq net.vrf.strict_mode=0
	ip -n "$srgw" -6 route add 2001:db8:bad1::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 64 \
			vrftable "${VRF_TABLE}" \
		dev veth-n3-srgw >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1
	ip netns exec "$srgw" sysctl -wq net.vrf.strict_mode=1

	log_test "$rc" 0 "End.M.GTP6.D vrftable rejected when strict_mode is off"
}

test_bad_vrftable()
{
	local rc=0

	ip -n "$srgw" -6 route add 2001:db8:bad2::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 64 \
			vrftable 0 \
		dev veth-n3-srgw >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1

	# Table not bound to any VRF device.
	ip -n "$srgw" -6 route add 2001:db8:bad3::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 64 \
			vrftable 9999 \
		dev veth-n3-srgw >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1

	log_test "$rc" 0 "End.M.GTP6.D rejects vrftable 0 and unbound table"
}

check_dependencies
setup

test_vrftable_positive
test_vrftable_required
test_strict_mode_off
test_bad_vrftable

print_log_test_results
exit "$ret"
