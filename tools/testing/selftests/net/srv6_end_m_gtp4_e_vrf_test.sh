#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Selftest for the SRv6 End.M.GTP4.E behavior with vrftable (RFC 9433).
#
#   +-------+  2001:db8:1::/64   +-------+   10.0.0.0/24    +-------+
#   | srupf | ------------------ |  srgw | --------------- |  gnb  |
#   +-------+      veth-n9       +-------+    veth-n3      +-------+
#                            (End.M.GTP4.E)
#
# Same per-namespace shape as srv6_end_m_gtp4_e_test.sh, but on srgw the
# GTP-U egress leg veth-n3 is enslaved into vrf-access (table 200) so the
# connected route to gnb (10.0.0.0/24) lives only in table 200.  The
# End.M.GTP4.E lwtunnel carries vrftable 200, so the egress IPv4 FIB
# lookup runs as if the rebuilt packet ingressed on the VRF master and
# resolves in that table.  Removing the attribute leaves the lookup in
# the main table where no route to gnb exists, proving the attribute is
# doing real work.

source lib.sh

readonly PING_TIMEOUT_SEC=4
readonly RECV_TIMEOUT_MS=2000

readonly SID="2001:db8:a00:2:1400:1:2300:0"
readonly TEID_HEX="0x00000123"
readonly QFI=5
readonly PDU_TYPE_DL=0
readonly V4_DST="10.0.0.2"
readonly V4_GW="10.0.0.254"
readonly V4_SRC="10.0.0.1"
readonly SRC6_DEFAULT="2001:db8:1::a00:1:0:1"
readonly VRF_TABLE=200

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

	for cmd in ip ping; do
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
	setup_ns srupf srgw gnb

	ip -n "$srupf" link set lo up
	ip -n "$srgw"  link set lo up
	ip -n "$gnb"   link set lo up

	# srupf <-> srgw (IPv6).
	ip link add veth-n9 netns "$srupf" \
		type veth peer name veth-n9-srgw netns "$srgw"
	ip -n "$srupf" addr add "${SRC6_DEFAULT}/64" dev veth-n9 nodad
	ip -n "$srgw"  addr add 2001:db8:1::2/64 dev veth-n9-srgw nodad
	ip -n "$srupf" link set veth-n9 up
	ip -n "$srgw"  link set veth-n9-srgw up

	ip netns exec "$srgw" sysctl -wq net.vrf.strict_mode=1
	ip -n "$srgw" link add vrf-access type vrf table "${VRF_TABLE}"
	ip -n "$srgw" link set vrf-access up

	# srgw <-> gnb (IPv4).  Enslave the egress leg BEFORE assigning its
	# address so the connected 10.0.0.0/24 route lands in the VRF table
	# and not in the main table.
	ip link add veth-n3 netns "$srgw" \
		type veth peer name veth-n3-gnb netns "$gnb"
	ip -n "$srgw" link set veth-n3 master vrf-access
	ip -n "$srgw" addr add "${V4_GW}/24" dev veth-n3
	ip -n "$gnb"  addr add "${V4_DST}/24" dev veth-n3-gnb
	ip -n "$srgw" link set veth-n3 up
	ip -n "$gnb"  link set veth-n3-gnb up

	ip netns exec "$srgw" sysctl -wq net.ipv4.ip_forward=1
	ip netns exec "$srgw" sysctl -wq net.ipv6.conf.all.forwarding=1

	# End.M.GTP4.E synthesises the IPv4 source from the IPv6 SA, so the
	# emitted GTP-U packet has no reverse route.  It is routed on the
	# input path, so rp_filter must be off for the synthetic source to
	# validate -- on the VRF master and its slave alike.
	ip netns exec "$srgw" sysctl -wq net.ipv4.conf.all.rp_filter=0
	ip netns exec "$srgw" sysctl -wq net.ipv4.conf.default.rp_filter=0

	# Disable HW checksum offload so the software checksum path runs.
	ip netns exec "$srupf" ethtool -K veth-n9 tx off rx off 2>/dev/null
	ip netns exec "$srgw"  ethtool -K veth-n9-srgw tx off rx off 2>/dev/null
	ip netns exec "$srgw"  ethtool -K veth-n3 tx off rx off 2>/dev/null
	ip netns exec "$gnb"   ethtool -K veth-n3-gnb tx off rx off 2>/dev/null

	ip -n "$srupf" -6 route add 2001:db8::/32 via 2001:db8:1::2
}

read_nstat_counter()
{
	local ns=$1
	local name=$2

	ip netns exec "$ns" nstat -az "$name" \
		| awk -v n="$name" '$1 == n {print $2}'
}

run_recv_match()
{
	local recv_pid before after rc=0

	before=$(read_nstat_counter "$gnb" UdpInCsumErrors)

	# Start the AF_PACKET receiver first; give it a brief moment to
	# attach before the ping packet hits the wire (the kernel does not
	# expose an "AF_PACKET ready" signal).
	ip netns exec "$gnb" "${RECV}" \
		-i veth-n3-gnb -m gtp4-e \
		-s "${V4_SRC}" -d "${V4_DST}" \
		-t "${TEID_HEX}" -q "${QFI}" -P "${PDU_TYPE_DL}" \
		-T "${RECV_TIMEOUT_MS}" \
		--pdu-session \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" \
			-I "${SRC6_DEFAULT}" "${SID}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || rc=$?

	after=$(read_nstat_counter "$gnb" UdpInCsumErrors)
	[ "$before" != "$after" ] && rc=1
	echo "$rc"
}

test_vrftable_positive()
{
	local rc

	ip -n "$srgw" -6 route add 2001:db8::/32 \
		encap seg6mobile action End.M.GTP4.E \
			sr_prefix_len 32 \
			pdu_type "${PDU_TYPE_DL}" \
			vrftable "${VRF_TABLE}" \
		dev veth-n9-srgw

	rc=$(run_recv_match)
	log_test "$rc" 0 "End.M.GTP4.E with vrftable steers egress into the access VRF"

	ip -n "$srgw" -6 route del 2001:db8::/32
}

test_vrftable_required()
{
	local rc

	# Same lwtunnel without vrftable: the egress lookup falls back to
	# the main table which has no path to gnb, so recv must time out.
	ip -n "$srgw" -6 route add 2001:db8::/32 \
		encap seg6mobile action End.M.GTP4.E \
			sr_prefix_len 32 \
			pdu_type "${PDU_TYPE_DL}" \
		dev veth-n9-srgw

	rc=$(run_recv_match)
	log_test "$rc" 2 "End.M.GTP4.E without vrftable fails to reach the access leg"

	ip -n "$srgw" -6 route del 2001:db8::/32
}

test_strict_mode_off()
{
	local rc=0

	ip netns exec "$srgw" sysctl -wq net.vrf.strict_mode=0
	ip -n "$srgw" -6 route add 2001:dbf:1::/32 \
		encap seg6mobile action End.M.GTP4.E \
			sr_prefix_len 32 \
			pdu_type "${PDU_TYPE_DL}" \
			vrftable "${VRF_TABLE}" \
		dev veth-n9-srgw >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1
	ip netns exec "$srgw" sysctl -wq net.vrf.strict_mode=1

	log_test "$rc" 0 "End.M.GTP4.E vrftable rejected when strict_mode is off"
}

test_bad_vrftable()
{
	local rc=0

	ip -n "$srgw" -6 route add 2001:dbf:2::/32 \
		encap seg6mobile action End.M.GTP4.E \
			sr_prefix_len 32 \
			pdu_type "${PDU_TYPE_DL}" \
			vrftable 0 \
		dev veth-n9-srgw >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1

	# Table not bound to any VRF device.
	ip -n "$srgw" -6 route add 2001:dbf:3::/32 \
		encap seg6mobile action End.M.GTP4.E \
			sr_prefix_len 32 \
			pdu_type "${PDU_TYPE_DL}" \
			vrftable 9999 \
		dev veth-n9-srgw >/dev/null 2>&1
	[ $? -eq 0 ] && rc=1

	log_test "$rc" 0 "End.M.GTP4.E rejects vrftable 0 and unbound table"
}

main()
{
	check_dependencies
	setup

	test_vrftable_positive
	test_vrftable_required
	test_strict_mode_off
	test_bad_vrftable

	print_log_test_results
	exit "${ret}"
}

main "$@"
