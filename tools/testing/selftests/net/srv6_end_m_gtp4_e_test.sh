#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Selftest for the SRv6 End.M.GTP4.E behavior (RFC 9433 Section 6.6).
#
#   +-------+  2001:db8:1::/64   +-------+   10.0.0.0/24    +-------+
#   | srupf | ------------------ |  srgw | --------------- |  gnb  |
#   +-------+      veth-n9       +-------+    veth-n3      +-------+
#                            (End.M.GTP4.E)
#
# srgw runs the End.M.GTP4.E behavior on a /32 locator.  The SID layout
# (RFC 9433 Section 6.6 Figure 9) packs the IPv4 destination (10.0.0.2 =
# gnb) at bytes 4..7 and Args.Mob.Session (40 bits: QFI(6) | R(1) |
# U(1) | TEID(32)) at bytes 8..12, giving the SID
# 2001:db8:a00:2:1400:1:2300:0 for QFI=5 / TEID=0x00000123.
#
# The IPv4 source address is recovered from the inbound IPv6 source by
# overlaying the configured src template with the v4_mask_len bits at
# bit offset v6_src_prefix_len (RFC 9433 Section 6.6 Figure 10).  Two
# srupf IPv6 source addresses are used to exercise the default /64 and
# an explicit /48 Source UPF Prefix layout.
#
# Each positive test case sends one ICMPv6 echo from srupf and uses an
# AF_PACKET recv helper on gnb's egress interface to compare every
# field of the resulting IPv4 / UDP / GTPv1-U [/ PDU Session] outer
# chain against the expected value.  The negative cases assert that no
# matching packet reaches gnb (drop) or that ip route add returns
# EINVAL (bad attribute combinations).
#
# Cases exercised:
#   1. SRH absent, default config (v6_src_prefix_len=64, pdu_type=dl)
#   2. SRH present (H.Encaps from srupf)
#   3. Explicit v6_src_prefix_len=48
#   4. No pdu_type   -- short GTPv1-U, no PDU Session ext
#   5. Malformed SRH -- drop
#   6. Bad attribute -- ip route add returns EINVAL

source lib.sh

readonly PING_TIMEOUT_SEC=4
readonly RECV_TIMEOUT_MS=2000

readonly SID_DEFAULT="2001:db8:a00:2:1400:1:2300:0"
readonly SID_V6PFX48="2001:db9:a00:2:1400:1:2300:0"
readonly SID_NOPDU="2001:dbb:a00:2:1400:1:2300:0"
readonly TEID_HEX="0x00000123"
readonly QFI=5
readonly PDU_TYPE_DL=0
readonly V4_DST="10.0.0.2"

# srupf IPv6 SA where IPv4 SA (10.0.0.1) lives at bytes 8..11 (P=64).
readonly SRC6_DEFAULT="2001:db8:1::a00:1:0:1"
# srupf IPv6 SA where IPv4 SA (10.0.0.1) lives at bytes 6..9  (P=48).
readonly SRC6_V6PFX48="2001:db8:3:a00:1::1"
readonly V4_SRC="10.0.0.1"

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

	if ! ip route help 2>&1 | grep -qF "End.M.GTP4.E"; then
		echo "SKIP: iproute2 lacks End.M.GTP4.E action"
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
	ip -n "$srupf" addr add "${SRC6_V6PFX48}/64" dev veth-n9 nodad
	ip -n "$srgw"  addr add 2001:db8:1::2/64    dev veth-n9-srgw nodad
	ip -n "$srgw"  addr add 2001:db8:3:a00:1::2/64 dev veth-n9-srgw nodad
	ip -n "$srupf" link set veth-n9 up
	ip -n "$srgw"  link set veth-n9-srgw up

	# srgw <-> gnb (IPv4).
	ip link add veth-n3 netns "$srgw" \
		type veth peer name veth-n3-gnb netns "$gnb"
	ip -n "$srgw" addr add "${V4_SRC}/24" dev veth-n3
	ip -n "$gnb"  addr add "${V4_DST}/24" dev veth-n3-gnb
	ip -n "$srgw" link set veth-n3 up
	ip -n "$gnb"  link set veth-n3-gnb up

	ip netns exec "$srgw" sysctl -wq net.ipv4.ip_forward=1
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

	# Routes on srupf toward the three End.M.GTP4.E locators.
	ip -n "$srupf" -6 route add 2001:db8::/32 via 2001:db8:1::2
	ip -n "$srupf" -6 route add 2001:db9::/32 via 2001:db8:3:a00:1::2
	ip -n "$srupf" -6 route add 2001:dbb::/32 via 2001:db8:1::2

	# End.M.GTP4.E on srgw with PDU Session Container, default
	# /64 Source UPF Prefix.
	ip -n "$srgw" -6 route add 2001:db8::/32 \
		encap seg6mobile action End.M.GTP4.E \
			src 2001:db8:1::2 v4_mask_len 32 pdu_type "${PDU_TYPE_DL}" \
		dev veth-n3

	# End.M.GTP4.E on srgw with PDU Session Container, explicit
	# /48 Source UPF Prefix.
	ip -n "$srgw" -6 route add 2001:db9::/32 \
		encap seg6mobile action End.M.GTP4.E \
			src 2001:db9::1 v4_mask_len 32 v6_src_prefix_len 48 \
			pdu_type "${PDU_TYPE_DL}" \
		dev veth-n3

	# End.M.GTP4.E on srgw WITHOUT pdu_type: short GTPv1-U,
	# no PDU Session Container.
	ip -n "$srgw" -6 route add 2001:dbb::/32 \
		encap seg6mobile action End.M.GTP4.E \
			src 2001:db8:1::2 v4_mask_len 32 \
		dev veth-n3
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
	local sid="$1"
	local src6="$2"
	local v4src="$3"
	local extra=("${@:4}")	# extra args to recv (e.g. --pdu-session)
	local recv_pid before after rc=0

	before=$(read_nstat_counter "$gnb" UdpInCsumErrors)

	# Start the AF_PACKET receiver first; give it a brief moment to
	# attach before the ping packet hits the wire (the kernel does
	# not expose an "AF_PACKET ready" signal).
	ip netns exec "$gnb" "${RECV}" \
		-i veth-n3-gnb -m gtp4-e \
		-s "$v4src" -d "${V4_DST}" \
		-t "${TEID_HEX}" -q "${QFI}" -P "${PDU_TYPE_DL}" \
		-T "${RECV_TIMEOUT_MS}" \
		"${extra[@]}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" -I "${src6}" "${sid}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || rc=$?

	after=$(read_nstat_counter "$gnb" UdpInCsumErrors)
	[ "$before" != "$after" ] && rc=1
	echo "$rc"
}

# Test 1: SRH absent, default config.
test_default()
{
	local rc

	rc=$(run_recv_match "${SID_DEFAULT}" "${SRC6_DEFAULT}" "${V4_SRC}" \
		--pdu-session)
	log_test "$rc" 0 "End.M.GTP4.E SRH-less, default v6_src_prefix_len, PDU Session"
}

# Test 2: SRH present (H.Encaps from srupf).
test_srh_present()
{
	local rc

	# H.Encaps wraps the inner ICMPv6 in IPv6+SRH.  End.M.GTP4.E
	# derives the outer IPv4 SA from the OUTER IPv6 SA (added by
	# H.Encaps, not the inner -I binding), so the encap route must
	# pin the outer SA with tunsrc for the expected IPv4 SA to be
	# deterministic across address-selection tiebreakers.
	ip -n "$srupf" -6 route add 2001:db8:f::1/128 via 2001:db8:1::2 \
		encap seg6 mode encap segs "${SID_DEFAULT}" \
			tunsrc "${SRC6_DEFAULT}" \
		dev veth-n9

	rc=$(run_recv_match 2001:db8:f::1 "${SRC6_DEFAULT}" "${V4_SRC}" \
		--pdu-session)
	log_test "$rc" 0 "End.M.GTP4.E preserves outer fields with an H.Encaps SRH"
}

# Test 3: Explicit v6_src_prefix_len=48.
test_v6_src_prefix_48()
{
	local rc

	rc=$(run_recv_match "${SID_V6PFX48}" "${SRC6_V6PFX48}" "${V4_SRC}" \
		--pdu-session)
	log_test "$rc" 0 "End.M.GTP4.E with explicit v6_src_prefix_len=48"
}

# Test 4: No pdu_type configured  -- expect short GTPv1-U, no PDU Session.
test_no_pdu_type()
{
	local recv_pid before after rc=0

	before=$(read_nstat_counter "$gnb" UdpInCsumErrors)

	ip netns exec "$gnb" "${RECV}" \
		-i veth-n3-gnb -m gtp4-e \
		-s "${V4_SRC}" -d "${V4_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" \
			-I "${SRC6_DEFAULT}" "${SID_NOPDU}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || rc=$?

	after=$(read_nstat_counter "$gnb" UdpInCsumErrors)
	[ "$before" != "$after" ] && rc=1

	log_test "$rc" 0 "End.M.GTP4.E without pdu_type emits short GTPv1-U"
}

# Test 5: Malformed SRH -- the SRv6 handler must drop, so recv times out.
test_srh_malformed()
{
	local recv_pid rc=0 recv_rc

	ip netns exec "$gnb" "${RECV}" \
		-i veth-n3-gnb -m gtp4-e \
		-s "${V4_SRC}" -d "${V4_DST}" \
		-t "${TEID_HEX}" -q "${QFI}" -P "${PDU_TYPE_DL}" \
		-T "${RECV_TIMEOUT_MS}" \
		--pdu-session \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$srupf" "${SEND}" \
		"${SRC6_DEFAULT}" "${SID_DEFAULT}" \
		>/dev/null 2>&1

	wait "$recv_pid" || recv_rc=$?
	# Expected: timeout (no packet) = exit 2.
	[ "${recv_rc:-0}" -ne 2 ] && rc=1

	log_test "$rc" 0 "End.M.GTP4.E drops a packet carrying a malformed SRH"
}

# Test 6: bad attribute values must be rejected at config time.
test_bad_attrs()
{
	local rc=0

	# v4_mask_len = 0 (parse-time check).
	if ip -n "$srgw" -6 route add 2001:dbf:0::/32 \
		encap seg6mobile action End.M.GTP4.E \
			src 2001:db8:1::2 v4_mask_len 0 \
		dev veth-n3 2>/dev/null; then
		rc=1
	fi

	# v4_mask_len = 33 (parse-time check).
	if ip -n "$srgw" -6 route add 2001:dbf:1::/32 \
		encap seg6mobile action End.M.GTP4.E \
			src 2001:db8:1::2 v4_mask_len 33 \
		dev veth-n3 2>/dev/null; then
		rc=1
	fi

	# v6_src_prefix_len = 97 (validate callback: 97 + 32 > 128).
	if ip -n "$srgw" -6 route add 2001:dbf:2::/32 \
		encap seg6mobile action End.M.GTP4.E \
			src 2001:db8:1::2 v4_mask_len 32 v6_src_prefix_len 97 \
		dev veth-n3 2>/dev/null; then
		rc=1
	fi

	# pdu_type = 16 (parse-time check: PDU Type is a 4-bit field).
	if ip -n "$srgw" -6 route add 2001:dbf:3::/32 \
		encap seg6mobile action End.M.GTP4.E \
			src 2001:db8:1::2 v4_mask_len 32 pdu_type 16 \
		dev veth-n3 2>/dev/null; then
		rc=1
	fi

	log_test "$rc" 0 "End.M.GTP4.E rejects bad attribute values at ip route add"
}

main()
{
	check_dependencies
	setup

	test_default
	test_srh_present
	test_v6_src_prefix_48
	test_no_pdu_type
	test_srh_malformed
	test_bad_attrs

	print_log_test_results
	exit "${ret}"
}

main "$@"
