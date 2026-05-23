#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# author: Yuya Kusakabe <yuya.kusakabe@gmail.com>

# Selftest for the SRv6 End.MAP behavior (RFC 9433).
#
#   +------+    2001:db8:1::/64    +------+    2001:db8:2::/64    +------+
#   | rt-1 | --------------------- | rt-2 | --------------------- | rt-3 |
#   +------+         veth1         +------+         veth2         +------+
#                                 (End.MAP)
#
# rt-2 holds the End.MAP route for 2001:db8:f::/64 that replaces the
# IPv6 destination with 2001:db8:3::3 (an address on rt-3's loopback).
# rt-3 also owns 2001:db8:4::4, which rt-2 has no route to, so it is
# reachable only as the last segment of an SRH that End.MAP leaves for
# rt-3 to process.
#
# The original destination 2001:db8:f::1 and the replacement
# 2001:db8:3::3 have different 16-bit word sums, so a missing or wrong
# transport checksum update makes rt-3 count a checksum error instead of
# answering.
#
# The cases cover:
#
#   - the transport checksum: patched for ICMPv6, UDP and TCP without an
#     SRH, with an exhausted SRH and on the first fragment, and left
#     alone while an SRH is still active, also one behind a type 0
#     Routing Header with Segments Left 0;
#   - the SRH: forwarded intact, so that rt-3 rather than End.MAP
#     processes it;
#   - Routing Header validation: a non-SRH Routing Header is ignored
#     with Segments Left 0 and dropped otherwise, and a malformed SRH
#     or one without the HMAC that seg6_require_hmac asks for is
#     dropped, also behind a type 0 Routing Header;
#   - the Hop Limit: an echo arriving with Hop Limit 1 gets a Time
#     Exceeded that quotes the End.MAP SID, also with a local mapped
#     SID, and one arriving with Hop Limit 2 still reaches rt-3;
#   - packets without a checksum to patch, which End.MAP forwards: No
#     Next Header and a truncated TCP header;
#   - the errors counter for an IPv4 packet routed through a nexthop
#     object carrying End.MAP.

source lib.sh

readonly PING_TIMEOUT_SEC=4
readonly COUNTER_TIMEOUT_SEC=2
readonly END_MAP_PREFIX="2001:db8:f::/64"
readonly END_MAP_SID="2001:db8:f::1"
readonly RT3_SID="2001:db8:3::3"
readonly RT3_FINAL="2001:db8:4::4"
readonly LOCAL_MAP_PREFIX="2001:db8:e::/64"
readonly LOCAL_MAP_SID="2001:db8:e::1"
readonly NH_ID=100
HELPER_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly HELPER_DIR
readonly HELPER="${HELPER_DIR}/srv6_mobile_send"

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

	for cmd in ip ping nstat sysctl ethtool grep; do
		if ! command -v "$cmd" >/dev/null; then
			echo "SKIP: ${cmd} is required"
			exit "${ksft_skip}"
		fi
	done

	if [ ! -x "${HELPER}" ]; then
		echo "SKIP: ${HELPER} not built"
		exit "${ksft_skip}"
	fi

	if ! ip route help 2>&1 | grep -qF "seg6mobile"; then
		echo "SKIP: iproute2 lacks seg6mobile support"
		exit "${ksft_skip}"
	fi

	if ! ip route help 2>&1 | grep -qF "End.MAP"; then
		echo "SKIP: iproute2 lacks End.MAP action"
		exit "${ksft_skip}"
	fi
}

setup()
{
	setup_ns rt1 rt2 rt3

	# shellcheck disable=SC2154 # variables assigned by setup_ns
	for ns in "$rt1" "$rt2" "$rt3"; do
		ip -n "$ns" link set lo up
	done

	ip link add veth1 netns "$rt1" \
		type veth peer name veth1-rt2 netns "$rt2"
	ip link add veth2 netns "$rt2" \
		type veth peer name veth2-rt3 netns "$rt3"

	ip -n "$rt1" addr add 2001:db8:1::1/64 dev veth1 nodad
	ip -n "$rt2" addr add 2001:db8:1::2/64 dev veth1-rt2 nodad
	ip -n "$rt2" addr add 2001:db8:2::1/64 dev veth2 nodad
	ip -n "$rt3" addr add 2001:db8:2::2/64 dev veth2-rt3 nodad
	# rt-3 also owns the End.MAP replacement SID / SRH endpoint.
	ip -n "$rt3" addr add "$RT3_SID/128" dev lo nodad
	ip -n "$rt3" addr add "$RT3_FINAL/128" dev lo nodad
	ip -n "$rt1" addr add 10.0.1.1/24 dev veth1
	ip -n "$rt2" addr add 10.0.1.2/24 dev veth1-rt2

	ip -n "$rt1" link set veth1 up
	ip -n "$rt2" link set veth1-rt2 up
	ip -n "$rt2" link set veth2 up
	ip -n "$rt3" link set veth2-rt3 up

	ip netns exec "$rt2" sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$rt2" sysctl -wq net.ipv4.ip_forward=1

	# rt-3 must accept SRv6 packets so ipv6_srh_rcv lets the
	# extension header chain through to local delivery.
	ip netns exec "$rt3" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$rt3" \
		sysctl -wq net.ipv6.conf.veth2-rt3.seg6_enabled=1
	ip netns exec "$rt3" sysctl -wq net.ipv6.conf.lo.seg6_enabled=1

	# Disable HW checksum offload so the kernel software checksum
	# path runs unconditionally and any csum bug surfaces.
	ip netns exec "$rt1" ethtool -K veth1 tx off rx off
	ip netns exec "$rt2" ethtool -K veth1-rt2 tx off rx off
	ip netns exec "$rt2" ethtool -K veth2 tx off rx off
	ip netns exec "$rt3" ethtool -K veth2-rt3 tx off rx off

	# rt-1: route the End.MAP locators into rt-2.
	ip -n "$rt1" -6 route add "$END_MAP_PREFIX" via 2001:db8:1::2
	ip -n "$rt1" -6 route add "$LOCAL_MAP_PREFIX" via 2001:db8:1::2
	ip -n "$rt1" route add 10.9.9.0/24 via 10.0.1.2

	# rt-1: an H.Encaps route whose SRH ends at RT3_FINAL, so that the
	# echo arrives only if rt-3 processes the SRH End.MAP left alone.
	ip -n "$rt1" -6 route add "$RT3_FINAL/128" via 2001:db8:1::2 \
		encap seg6 mode encap \
		segs "$END_MAP_SID","$RT3_FINAL" \
		dev veth1

	# rt-2: End.MAP -- swap DA from the End.MAP SID to RT3_SID
	# (an address on rt-3) and forward via the IPv6 FIB.  "count"
	# enables the per-behavior counters the drop tests read.
	ip -n "$rt2" -6 route add "$END_MAP_PREFIX" \
		encap seg6mobile action End.MAP mapped_sid "$RT3_SID" count \
		dev veth2

	# rt-2: End.MAP towards rt-2's own address, delivered locally.
	ip -n "$rt2" -6 route add "$LOCAL_MAP_PREFIX" \
		encap seg6mobile action End.MAP mapped_sid 2001:db8:2::1 \
		dev veth2

	# rt-2: End.MAP in a nexthop object that an IPv4 route uses.
	ip -n "$rt2" -6 nexthop add id "$NH_ID" via 2001:db8:2::2 \
		encap seg6mobile action End.MAP mapped_sid "$RT3_SID" count \
		dev veth2
	ip -n "$rt2" route add 10.9.9.0/24 nhid "$NH_ID"

	# rt-2: reach RT3_SID (on rt-3's loopback) through the
	# directly connected neighbour 2001:db8:2::2.
	ip -n "$rt2" -6 route add "$RT3_SID/128" via 2001:db8:2::2

	# rt-3: return route for the ICMPv6 echo reply.
	ip -n "$rt3" -6 route add 2001:db8:1::/64 via 2001:db8:2::1
}

read_nstat_counter()
{
	local ns=$1
	local name=$2

	# nstat -az reports a counter that has never incremented as 0,
	# which is what we rely on for a clean before/after delta.
	ip netns exec "$ns" nstat -az "$name" \
		| awk -v n="$name" '$1 == n {print $2}'
}

read_route_counter()
{
	local name=$1

	ip -n "$rt2" -j -s -6 route show "$END_MAP_PREFIX" \
		| grep -oE "\"${name}\":[0-9]+" | grep -oE '[0-9]+'
}

read_nexthop_errors()
{
	ip -n "$rt2" -s nexthop show id "$NH_ID" \
		| grep -oE 'errors [0-9]+' | grep -oE '[0-9]+'
}

read_route_errors()
{
	# The End.MAP route carries "count", so its errors counter
	# increments once for every packet the behavior drops.  Reading it
	# binds the negative test to the drop itself rather than to any
	# unrelated loss on the path to rt-3.
	read_route_counter errors
}

test_srh_absent()
{
	local before after rc=0

	before=$(read_nstat_counter "$rt3" Icmp6InCsumErrors)

	if ! ip netns exec "$rt1" \
			ping -6 -c 1 -W "$PING_TIMEOUT_SEC" "$END_MAP_SID" \
			>/dev/null 2>&1; then
		rc=1
	fi

	if [ "$rc" -eq 0 ]; then
		after=$(read_nstat_counter "$rt3" Icmp6InCsumErrors)
		[ "$before" != "$after" ] && rc=1
	fi

	log_test "$rc" 0 "End.MAP forwards an ICMPv6 echo without an SRH"
}

test_srh_present()
{
	local before after rc=0

	before=$(read_nstat_counter "$rt3" Icmp6InCsumErrors)

	if ! ip netns exec "$rt1" \
			ping -6 -c 1 -W "$PING_TIMEOUT_SEC" "$RT3_FINAL" \
			>/dev/null 2>&1; then
		rc=1
	fi

	if [ "$rc" -eq 0 ]; then
		after=$(read_nstat_counter "$rt3" Icmp6InCsumErrors)
		[ "$before" != "$after" ] && rc=1
	fi

	log_test "$rc" 0 "End.MAP leaves the SRH for rt-3 to process"
}

test_srh_inline()
{
	local before after rc=0

	ip -n "$rt1" -6 route add 2001:db8:2::2/128 via 2001:db8:1::2 \
		encap seg6 mode inline segs "$END_MAP_SID" \
		dev veth1

	before=$(read_nstat_counter "$rt3" Icmp6InCsumErrors)

	if ! ip netns exec "$rt1" \
			ping -6 -c 1 -W "$PING_TIMEOUT_SEC" 2001:db8:2::2 \
			>/dev/null 2>&1; then
		rc=1
	fi

	if [ "$rc" -eq 0 ]; then
		after=$(read_nstat_counter "$rt3" Icmp6InCsumErrors)
		[ "$before" != "$after" ] && rc=1
	fi

	log_test "$rc" 0 "End.MAP preserves L4 csum across mode inline SRH"
}

# The drop happens on rt-2's receive path, asynchronously to the
# sender, so wait for the errors counter instead of sampling it.
expect_end_map_drop()
{
	local before rc=0

	before=$(read_route_errors)

	ip netns exec "$rt1" "$HELPER" -m end-map "$@" \
		-s 2001:db8:1::1 -d "$END_MAP_SID" >/dev/null 2>&1

	slowwait "$COUNTER_TIMEOUT_SEC" until_counter_is ">= $((before + 1))" \
		read_route_errors >/dev/null || rc=1
	[ "$(read_route_errors)" -eq "$((before + 1))" ] || rc=1

	echo "$rc"
}

# Sends a helper-crafted packet through End.MAP and waits for rt-3 to
# accept it: the first counter is the one rt-3 bumps when the transport
# checksum verifies, the second the one it bumps when it does not.
expect_rt3_rx()
{
	local ok_cnt=$1 err_cnt=$2
	local before_ok before_err rc=0

	shift 2
	before_ok=$(read_nstat_counter "$rt3" "$ok_cnt")
	before_err=$(read_nstat_counter "$rt3" "$err_cnt")

	ip netns exec "$rt1" "$HELPER" -m end-map "$@" \
		-s 2001:db8:1::1 -d "$END_MAP_SID" >/dev/null 2>&1

	slowwait "$COUNTER_TIMEOUT_SEC" \
		until_counter_is ">= $((before_ok + 1))" \
		read_nstat_counter "$rt3" "$ok_cnt" >/dev/null || rc=1
	[ "$(read_nstat_counter "$rt3" "$err_cnt")" -eq "$before_err" ] ||
		rc=1

	echo "$rc"
}

expect_end_map_echo()
{
	expect_rt3_rx Icmp6InEchos Icmp6InCsumErrors "$@"
}

# Sends a helper-crafted packet that has no checksum for End.MAP to
# patch; the behavior's packets counter binds the assertion.
expect_end_map_fwd()
{
	local before_pkts before_errs rc=0

	before_pkts=$(read_route_counter packets)
	before_errs=$(read_route_errors)

	ip netns exec "$rt1" "$HELPER" -m end-map "$@" \
		-s 2001:db8:1::1 -d "$END_MAP_SID" >/dev/null 2>&1

	slowwait "$COUNTER_TIMEOUT_SEC" \
		until_counter_is ">= $((before_pkts + 1))" \
		read_route_counter packets >/dev/null || rc=1
	[ "$(read_route_errors)" -eq "$before_errs" ] || rc=1

	echo "$rc"
}

test_rh_not_srh()
{
	local rc

	rc=$(expect_end_map_echo --rh-type 0)
	log_test "$rc" 0 "End.MAP ignores a non-SRH RH with Segments Left 0"
}

test_rh_not_srh_segleft()
{
	local rc

	rc=$(expect_end_map_drop --rh-type 0 --segleft 1)
	log_test "$rc" 0 "End.MAP drops a non-SRH RH with Segments Left 1"
}

test_srh_malformed()
{
	local rc

	rc=$(expect_end_map_drop --bad-srh)
	log_test "$rc" 0 "End.MAP drops a malformed SRH"
}

# A type 0 Routing Header with Segments Left 0 is ignored, so the
# Routing Header behind it must get the same checks.
test_behind_rh0()
{
	local rc

	rc=$(expect_end_map_drop --pre-rh0 --bad-srh)
	log_test "$rc" 0 "End.MAP drops a malformed SRH behind a type 0 RH"

	rc=$(expect_end_map_drop --pre-rh0 --rh-type 0 --segleft 1)
	log_test "$rc" 0 "End.MAP drops a type 0 RH with SL 1 behind another"

	# The echo checksum covers the segment, not the End.MAP SID.
	rc=$(expect_end_map_echo --pre-rh0 --segleft 1 --segment "$RT3_SID")
	log_test "$rc" 0 "End.MAP keeps the L4 csum behind a type 0 RH"
}

test_hmac_required()
{
	local rc

	if ! ip netns exec "$rt2" sysctl -wq \
			net.ipv6.conf.veth1-rt2.seg6_require_hmac=1 \
			2>/dev/null; then
		echo "SKIP: HMAC tests, kernel lacks CONFIG_IPV6_SEG6_HMAC"
		return
	fi

	rc=$(expect_end_map_drop)
	log_test "$rc" 0 "End.MAP drops an SRH without the required HMAC"

	rc=$(expect_end_map_drop --segleft 1 --segment "$RT3_SID")
	log_test "$rc" 0 "End.MAP drops an active SRH without the required HMAC"

	rc=$(expect_end_map_drop --pre-rh0)
	log_test "$rc" 0 "End.MAP drops an SRH without HMAC behind a type 0 RH"

	ip netns exec "$rt2" sysctl -wq \
		net.ipv6.conf.veth1-rt2.seg6_require_hmac=0
}

test_srh_exhausted()
{
	local rc

	rc=$(expect_end_map_echo)
	log_test "$rc" 0 "End.MAP patches the L4 csum of an exhausted SRH"
}

test_udp_tcp()
{
	local rc

	rc=$(expect_rt3_rx Udp6NoPorts Udp6InCsumErrors --no-rh --l4 udp)
	log_test "$rc" 0 "End.MAP patches the UDP csum"

	rc=$(expect_rt3_rx TcpOutRsts TcpInCsumErrors --no-rh --l4 tcp)
	log_test "$rc" 0 "End.MAP patches the TCP csum"
}

test_fragmented()
{
	local before after rc=0

	before=$(read_nstat_counter "$rt3" Icmp6InCsumErrors)

	if ! ip netns exec "$rt1" \
			ping -6 -c 1 -s 2000 -M dont -W "$PING_TIMEOUT_SEC" \
			"$END_MAP_SID" >/dev/null 2>&1; then
		rc=1
	fi

	if [ "$rc" -eq 0 ]; then
		after=$(read_nstat_counter "$rt3" Icmp6InCsumErrors)
		[ "$before" != "$after" ] && rc=1
	fi

	log_test "$rc" 0 "End.MAP patches the L4 csum of a fragmented echo"
}

# ping reports the Time Exceeded only if it quotes the address the echo
# was sent to.
expect_time_exceeded()
{
	local dst=$1

	ip netns exec "$rt1" \
		ping -6 -c 1 -t 1 -W "$PING_TIMEOUT_SEC" "$dst" 2>&1 |
		grep -q "Time exceeded"
}

test_hoplimit()
{
	local rc=0

	expect_time_exceeded "$END_MAP_SID" || rc=1
	log_test "$rc" 0 "End.MAP sends Time Exceeded for its own SID"

	rc=0
	expect_time_exceeded "$LOCAL_MAP_SID" || rc=1
	log_test "$rc" 0 "End.MAP sends Time Exceeded with a local mapped SID"

	rc=0
	ip netns exec "$rt1" \
		ping -6 -c 1 -t 2 -W "$PING_TIMEOUT_SEC" "$END_MAP_SID" \
		>/dev/null 2>&1 || rc=1
	log_test "$rc" 0 "End.MAP decrements the Hop Limit once"
}

test_no_l4_csum()
{
	local rc

	rc=$(expect_end_map_fwd --no-next-header)
	log_test "$rc" 0 "End.MAP forwards a packet with No Next Header"

	rc=$(expect_end_map_fwd --no-rh --l4 tcp --l4-len 8)
	log_test "$rc" 0 "End.MAP forwards a truncated TCP header"
}

test_ipv4_nexthop()
{
	local before rc=0

	before=$(read_nexthop_errors)

	ip netns exec "$rt1" ping -c 1 -W 1 10.9.9.1 >/dev/null 2>&1

	slowwait "$COUNTER_TIMEOUT_SEC" until_counter_is ">= $((before + 1))" \
		read_nexthop_errors >/dev/null || rc=1

	log_test "$rc" 0 "End.MAP counts an IPv4 packet it drops as an error"
}

main()
{
	check_dependencies
	setup

	test_srh_absent
	test_srh_present
	test_srh_inline
	test_rh_not_srh
	test_rh_not_srh_segleft
	test_srh_malformed
	test_behind_rh0
	test_hmac_required
	test_srh_exhausted
	test_udp_tcp
	test_fragmented
	test_hoplimit
	test_no_l4_csum
	test_ipv4_nexthop

	print_log_test_results
	exit "${ret}"
}

main "$@"
