#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Selftest for the SRv6 End.M.GTP6.E behavior (RFC 9433).
#
#   +-------+  2001:db8:1::/64   +-------+  2001:db8:3::/64  +-------+
#   | srupf | ------------------ |  srgw | ----------------- |  gnb  |
#   +-------+      veth-n9       +-------+      veth-n3      +-------+
#                            (End.M.GTP6.E)
#
# srgw runs the End.M.GTP6.E behavior on a /64 locator.  The SID layout
# packs Args.Mob.Session (40 bits: QFI(6) | R(1) | U(1) | TEID(32)) at
# bytes 8..12, giving the SID 2001:db8:e::1400:1:2300:0 for QFI=5 /
# TEID=0x00000123.
#
# Unlike End.M.GTP4.E, End.M.GTP6.E mandates an SRH with Segments
# Left == 1: the current SID is the penultimate segment and the final
# IPv6 destination of the new GTP-U tunnel is taken from SRH[0].  All
# positive cases therefore exercise an H.Encaps ingress that produces
# this SRH layout.
#
# The IPv6 outer source S is taken verbatim from the configured src
# attribute, with no per-packet derivation.  UDP/IPv6 checksums are
# mandatory; Udp6InCsumErrors must remain zero.
#
# Cases exercised:
#   1. SRH present, default config (no pdu_type)  -- short GTPv1-U
#   2. SRH present, pdu_type=dl                   -- GTPv1-U + PDU Session
#   3. SRH present with Segments Left == 0        -- drop
#   4. SRH absent                                 -- drop
#   5. Malformed SRH                              -- drop
#   6. Bad attribute                              -- ip route add returns EINVAL

source lib.sh

readonly PING_TIMEOUT_SEC=4
readonly RECV_TIMEOUT_MS=2000

readonly SID_DEFAULT="2001:db8:e::1400:1:2300:0"
readonly SID_PDU="2001:db8:f::1400:1:2300:0"
readonly TEID_HEX="0x00000123"
readonly QFI=5
readonly PDU_TYPE_DL=0

readonly SRC6_SRUPF="2001:db8:1::1"
readonly OUTER_SRC="2001:db8:2::1"
readonly OUTER_DST="2001:db8:3::2"

# A locally meaningless destination used as the trigger for H.Encaps
# on srupf.  The encap route turns the ICMPv6 echo into an SRv6 packet
# whose outer DA is the End.M.GTP6.E SID.
readonly TRIGGER_DEFAULT="2001:db8:1000::1"
readonly TRIGGER_PDU="2001:db8:1000::2"
readonly TRIGGER_SL0="2001:db8:1000::3"

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

	if ! ip route help 2>&1 | grep -qF "End.M.GTP6.E"; then
		echo "SKIP: iproute2 lacks End.M.GTP6.E action"
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
	ip -n "$srupf" addr add "${SRC6_SRUPF}/64" dev veth-n9 nodad
	ip -n "$srgw"  addr add 2001:db8:1::2/64    dev veth-n9-srgw nodad
	ip -n "$srupf" link set veth-n9 up
	ip -n "$srgw"  link set veth-n9-srgw up

	# srgw <-> gnb (IPv6).
	ip link add veth-n3 netns "$srgw" \
		type veth peer name veth-n3-gnb netns "$gnb"
	ip -n "$srgw" addr add 2001:db8:3::1/64 dev veth-n3 nodad
	ip -n "$gnb"  addr add "${OUTER_DST}/64" dev veth-n3-gnb nodad
	ip -n "$srgw" link set veth-n3 up
	ip -n "$gnb"  link set veth-n3-gnb up

	ip netns exec "$srgw" sysctl -wq net.ipv6.conf.all.forwarding=1

	# srupf must accept SRv6 sources for the H.Encaps test.
	ip netns exec "$srupf" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$srupf" sysctl -wq net.ipv6.conf.lo.seg6_enabled=1
	ip netns exec "$srupf" \
		sysctl -wq net.ipv6.conf.veth-n9.seg6_enabled=1

	# Disable HW checksum offload so the kernel software checksum
	# path runs unconditionally.
	ip netns exec "$srupf" ethtool -K veth-n9 tx off rx off 2>/dev/null
	ip netns exec "$srgw"  ethtool -K veth-n9-srgw tx off rx off 2>/dev/null
	ip netns exec "$srgw"  ethtool -K veth-n3 tx off rx off 2>/dev/null
	ip netns exec "$gnb"   ethtool -K veth-n3-gnb tx off rx off 2>/dev/null

	# Routes on srupf toward the End.M.GTP6.E locators.
	ip -n "$srupf" -6 route add 2001:db8:e::/64 via 2001:db8:1::2
	ip -n "$srupf" -6 route add 2001:db8:f::/64 via 2001:db8:1::2

	# End.M.GTP6.E on srgw without PDU Session.
	ip -n "$srgw" -6 route add 2001:db8:e::/64 \
		encap seg6mobile action End.M.GTP6.E \
			src "${OUTER_SRC}" \
		dev veth-n3

	# End.M.GTP6.E on srgw with PDU Session.
	ip -n "$srgw" -6 route add 2001:db8:f::/64 \
		encap seg6mobile action End.M.GTP6.E \
			src "${OUTER_SRC}" pdu_type "${PDU_TYPE_DL}" \
		dev veth-n3

	# H.Encaps triggers on srupf: ICMPv6 to TRIGGER_* is wrapped in
	# an outer SRv6 header carrying the SR policy
	# [End.M.GTP6.E SID, final IPv6 destination].  The SRH thus has
	# Segments Left == 1 and SRH[0] == OUTER_DST.
	ip -n "$srupf" -6 route add "${TRIGGER_DEFAULT}/128" \
		encap seg6 mode encap segs "${SID_DEFAULT},${OUTER_DST}" \
			tunsrc "${SRC6_SRUPF}" \
		dev veth-n9

	ip -n "$srupf" -6 route add "${TRIGGER_PDU}/128" \
		encap seg6 mode encap segs "${SID_PDU},${OUTER_DST}" \
			tunsrc "${SRC6_SRUPF}" \
		dev veth-n9

	# Single-segment H.Encaps for the SL == 0 negative test: the
	# outer DA is the End.M.GTP6.E SID but the SRH carries one
	# segment with SL == 0.
	ip -n "$srupf" -6 route add "${TRIGGER_SL0}/128" \
		encap seg6 mode encap segs "${SID_DEFAULT}" \
			tunsrc "${SRC6_SRUPF}" \
		dev veth-n9
}

read_nstat_counter()
{
	local ns=$1
	local name=$2

	ip netns exec "$ns" nstat -az "$name" \
		| awk -v n="$name" '$1 == n {print $2}'
}

# Run the AF_PACKET receiver on gnb, fire one ICMPv6 echo from srupf
# through the supplied H.Encaps trigger destination, and return the
# receiver's exit status.  A non-zero Udp6InCsumErrors delta during
# the window also fails the case (UDP/IPv6 mandates a non-zero
# checksum).
run_recv_match()
{
	local trigger="$1"
	local extra=("${@:2}")
	local recv_pid before after rc=0

	before=$(read_nstat_counter "$gnb" Udp6InCsumErrors)

	# Start the AF_PACKET receiver first; give it a brief moment to
	# attach before the ping packet hits the wire (the kernel does
	# not expose an "AF_PACKET ready" signal).
	ip netns exec "$gnb" "${RECV}" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" -q "${QFI}" -P "${PDU_TYPE_DL}" \
		-T "${RECV_TIMEOUT_MS}" \
		"${extra[@]}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" -I "${SRC6_SRUPF}" \
			"${trigger}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || rc=$?

	after=$(read_nstat_counter "$gnb" Udp6InCsumErrors)
	[ "$before" != "$after" ] && rc=1
	echo "$rc"
}

# Test 1: SRH present, no pdu_type configured -- short GTPv1-U.
test_default()
{
	local recv_pid before after rc=0

	before=$(read_nstat_counter "$gnb" Udp6InCsumErrors)

	ip netns exec "$gnb" "${RECV}" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" -I "${SRC6_SRUPF}" \
			"${TRIGGER_DEFAULT}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || rc=$?

	after=$(read_nstat_counter "$gnb" Udp6InCsumErrors)
	[ "$before" != "$after" ] && rc=1

	log_test "$rc" 0 "End.M.GTP6.E without pdu_type emits short GTPv1-U"
}

# Test 2: SRH present, pdu_type=dl -- long GTPv1-U + PDU Session.
test_pdu_session()
{
	local rc

	rc=$(run_recv_match "${TRIGGER_PDU}" --pdu-session)
	log_test "$rc" 0 "End.M.GTP6.E with pdu_type=dl emits PDU Session"
}

# Test 3: SRH present but Segments Left == 0 -- drop.
test_srh_sl0()
{
	local recv_pid rc=0 recv_rc

	ip netns exec "$gnb" "${RECV}" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" -I "${SRC6_SRUPF}" \
			"${TRIGGER_SL0}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || recv_rc=$?
	# Expected: timeout (no packet) = exit 2.
	[ "${recv_rc:-0}" -ne 2 ] && rc=1

	log_test "$rc" 0 "End.M.GTP6.E drops a packet with Segments Left == 0"
}

# Test 4: SRH absent -- a plain ICMPv6 echo direct to the SID, with
# no H.Encaps wrapper, must be dropped (End.M.GTP6.E requires SRH).
test_srh_absent()
{
	local recv_pid rc=0 recv_rc

	ip netns exec "$gnb" "${RECV}" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" -I "${SRC6_SRUPF}" \
			"${SID_DEFAULT}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || recv_rc=$?
	[ "${recv_rc:-0}" -ne 2 ] && rc=1

	log_test "$rc" 0 "End.M.GTP6.E drops a packet carrying no SRH"
}

# Test 5: Malformed SRH -- the SRv6 handler must drop, so recv times out.
test_srh_malformed()
{
	local recv_pid rc=0 recv_rc

	ip netns exec "$gnb" "${RECV}" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$srupf" "${SEND}" \
		"${SRC6_SRUPF}" "${SID_DEFAULT}" \
		>/dev/null 2>&1

	wait "$recv_pid" || recv_rc=$?
	# Expected: timeout (no packet) = exit 2.
	[ "${recv_rc:-0}" -ne 2 ] && rc=1

	log_test "$rc" 0 "End.M.GTP6.E drops a packet carrying a malformed SRH"
}

# Test 6: bad attribute values must be rejected at config time.
test_bad_attrs()
{
	local rc=0

	# pdu_type = 16 (parse-time check: PDU Type is a 4-bit field).
	if ip -n "$srgw" -6 route add 2001:dbf:0::/64 \
		encap seg6mobile action End.M.GTP6.E \
			src "${OUTER_SRC}" pdu_type 16 \
		dev veth-n3 2>/dev/null; then
		rc=1
	fi

	# Missing src (required attribute).
	if ip -n "$srgw" -6 route add 2001:dbf:1::/64 \
		encap seg6mobile action End.M.GTP6.E \
		dev veth-n3 2>/dev/null; then
		rc=1
	fi

	log_test "$rc" 0 "End.M.GTP6.E rejects bad attribute values at ip route add"
}

main()
{
	check_dependencies
	setup

	test_default
	test_pdu_session
	test_srh_sl0
	test_srh_absent
	test_srh_malformed
	test_bad_attrs

	print_log_test_results
	exit "${ret}"
}

main "$@"
