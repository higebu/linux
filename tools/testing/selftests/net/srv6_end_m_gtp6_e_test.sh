#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# author: Yuya Kusakabe <yuya.kusakabe@gmail.com>

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
# mandatory; Udp6InCsumErrors must remain zero.  With the optional
# udp6_zerocsum_tx attribute the emitted UDP checksum is zero instead
# (RFC 6935).
#
# Cases exercised:
#   1. SRH present, default config (no pdu_type)  -- short GTPv1-U
#   2. SRH present, pdu_type=dl                   -- GTPv1-U + PDU Session
#   3. SRH present with Segments Left == 0 or 2   -- drop
#   4. SRH absent                                 -- drop
#   5. Malformed SRH                              -- drop
#   6. Bad attribute                              -- ip route add returns EINVAL
#   7. Emitted GTP-U routed on the input path     -- traverses NF_INET_FORWARD
#   8. udp6_zerocsum_tx set                       -- zero UDP checksum on the wire
#   9. Traffic Class and Hop Limit                -- copied; ip6_forward()
#                                                    decrements the latter
#  10. Hop Limit 1                                -- Time Exceeded to sender
#  11. GSO T-PDU                                  -- a GTP-U packet with its
#                                                    own GTP-U Length and an
#                                                    intact T-PDU per segment

source lib.sh

readonly PING_TIMEOUT_SEC=4
readonly RECV_TIMEOUT_MS=2000

readonly SID_DEFAULT="2001:db8:e::1400:1:2300:0"
readonly SID_PDU="2001:db8:f::1400:1:2300:0"
readonly SID_ZEROCSUM="2001:db8:c::1400:1:2300:0"
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
readonly TRIGGER_ZEROCSUM="2001:db8:1000::4"
readonly TRIGGER_SL2="2001:db8:1000::5"

HELPER_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly HELPER_DIR
readonly RECV="${HELPER_DIR}/srv6_mobile_recv"
readonly SEND="${HELPER_DIR}/srv6_mobile_send"
readonly GSO_SEND="${HELPER_DIR}/srv6_mobile_gso_send"

# GSO case: a TCP TSO super-frame carrying GSO_NSEGS segments of GSO_SEG
# bytes, injected on a UE leg and forwarded into End.M.GTP6.E via H.Encaps.
readonly GSO_SEG=1000
readonly GSO_NSEGS=10
readonly GSO_INNER_SRC="2001:db8:aaaa::1"
readonly TRIGGER_GSO="2001:db8:1000::9"

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
	ip -n "$srupf" -6 route add 2001:db8:c::/64 via 2001:db8:1::2

	# End.M.GTP6.E on srgw without PDU Session.
	ip -n "$srgw" -6 route add 2001:db8:e::/64 \
		encap seg6mobile action End.M.GTP6.E \
			sr_prefix_len 64 \
			src "${OUTER_SRC}" count \
		dev veth-n3

	# End.M.GTP6.E on srgw with PDU Session.
	ip -n "$srgw" -6 route add 2001:db8:f::/64 \
		encap seg6mobile action End.M.GTP6.E \
			sr_prefix_len 64 \
			src "${OUTER_SRC}" pdu_type "${PDU_TYPE_DL}" \
		dev veth-n3

	# End.M.GTP6.E on srgw with zero-checksum transmit (RFC 6935).
	ip -n "$srgw" -6 route add 2001:db8:c::/64 \
		encap seg6mobile action End.M.GTP6.E \
			sr_prefix_len 64 \
			src "${OUTER_SRC}" udp6_zerocsum_tx \
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

	ip -n "$srupf" -6 route add "${TRIGGER_ZEROCSUM}/128" \
		encap seg6 mode encap segs "${SID_ZEROCSUM},${OUTER_DST}" \
			tunsrc "${SRC6_SRUPF}" \
		dev veth-n9

	# Single-segment H.Encaps for the SL == 0 negative test: the
	# outer DA is the End.M.GTP6.E SID but the SRH carries one
	# segment with SL == 0.
	ip -n "$srupf" -6 route add "${TRIGGER_SL0}/128" \
		encap seg6 mode encap segs "${SID_DEFAULT}" \
			tunsrc "${SRC6_SRUPF}" \
		dev veth-n9

	# Three-segment H.Encaps: the SID is reached with Segments Left 2,
	# so it is not the penultimate segment.
	ip -n "$srupf" -6 route add "${TRIGGER_SL2}/128" \
		encap seg6 mode encap \
			segs "${SID_DEFAULT},2001:db8:3::99,${OUTER_DST}" \
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

# Start the AF_PACKET receiver in the background and return once it has
# bound to its interface (it writes "ready" to the file passed with -r),
# so the probe cannot be sent before the receiver is attached.  Sets
# recv_pid for the caller.
start_recv()
{
	local ns=$1; shift
	local ready

	ready=$(mktemp)
	ip netns exec "$ns" "${RECV}" "$@" -r "$ready" >/dev/null 2>&1 &
	recv_pid=$!
	busywait 2000 grep -q ready "$ready" >/dev/null
	rm -f "$ready"
}

# tcpdump reports "listening on <iface>" on stderr once its capture is
# active; wait for that line in the given stderr file so the probe
# cannot be sent before the capture has started.
wait_tcpdump_listening()
{
	busywait 3000 grep -q "listening on" "$1" >/dev/null
}

read_route_errors()
{
	ip -n "$srgw" -s -6 route show 2001:db8:e::/64 |
		grep -oE 'errors [0-9]+' | grep -oE '[0-9]+'
}

# Capture on gnb for 3 seconds with the pcap filter @1 into cap_out, once
# the capture has started.
start_capture()
{
	cap_out=$(mktemp)
	cap_err=$(mktemp)
	ip netns exec "$gnb" timeout 3 tcpdump -p -l -n -i veth-n3-gnb "$1" \
		>"$cap_out" 2>"$cap_err" &
	cap_pid=$!
	wait_tcpdump_listening "$cap_err"
}

# Wait for the capture to end, and set cap_count to the number of packets
# in it.  This must not run in a subshell, which cannot wait for it.
capture_count()
{
	wait "$cap_pid" 2>/dev/null
	cap_count=$(grep -c '^[0-9]' "$cap_out")
	rm -f "$cap_out" "$cap_err"
}

# The GTP-U packet from OUTER_SRC to OUTER_DST, with UDP and GTP-U lengths
# that match the IPv6 Payload Length.
readonly GTPU_FILTER="ip6 src ${OUTER_SRC} and dst ${OUTER_DST} and \
udp port 2152 and ip6[44:2] = ip6[4:2] and ip6[50:2] + 16 = ip6[44:2]"

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

	start_recv "$gnb" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" -q "${QFI}" -P "${PDU_TYPE_DL}" \
		-T "${RECV_TIMEOUT_MS}" \
		"${extra[@]}"

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

	start_recv "$gnb" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}"

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

	start_recv "$gnb" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}"

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" -I "${SRC6_SRUPF}" \
			"${TRIGGER_SL0}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || recv_rc=$?
	# Expected: timeout (no packet) = exit 2.
	[ "${recv_rc:-0}" -ne 2 ] && rc=1

	log_test "$rc" 0 "End.M.GTP6.E drops a packet with Segments Left == 0"
}

# SRH present with Segments Left == 2: End.M.GTP6.E must be the
# penultimate segment, so the packet is dropped and counted as an error.
test_srh_sl2()
{
	local recv_pid rc=0 recv_rc errors

	errors=$(read_route_errors)
	start_recv "$gnb" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}"

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" -I "${SRC6_SRUPF}" \
			"${TRIGGER_SL2}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || recv_rc=$?
	[ "${recv_rc:-0}" -ne 2 ] && rc=1
	[ "$(read_route_errors)" -eq "$((errors + 1))" ] || rc=1

	log_test "$rc" 0 "End.M.GTP6.E drops a packet with Segments Left == 2"
}

# Test 4: SRH absent -- a plain ICMPv6 echo direct to the SID, with
# no H.Encaps wrapper, must be dropped (End.M.GTP6.E requires SRH).
test_srh_absent()
{
	local recv_pid rc=0 recv_rc

	start_recv "$gnb" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}"

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
	local recv_pid rc=0 recv_rc errors

	errors=$(read_route_errors)
	start_recv "$gnb" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}"

	ip netns exec "$srupf" "${SEND}" -m end-map \
		-s "${SRC6_SRUPF}" -d "${SID_DEFAULT}" --bad-srh \
		>/dev/null 2>&1 || rc=1

	wait "$recv_pid" || recv_rc=$?
	# Expected: timeout (no packet) = exit 2.
	[ "${recv_rc:-0}" -ne 2 ] && rc=1
	[ "$(read_route_errors)" -eq "$((errors + 1))" ] || rc=1

	log_test "$rc" 0 "End.M.GTP6.E drops a packet carrying a malformed SRH"
}

# Test 6: fragmented outer -- an inbound IPv6 packet carrying a Fragment
# extension header must be dropped, because ipv6_skip_exthdr() reports a
# nonzero frag_off.  H.Encaps on srupf wraps a large ICMPv6 echo in an
# outer SRv6 header; the oversized result is fragmented at the source, so
# the first fragment reaches srgw as IPv6/SRH/Fragment/.... Absent the
# check End.M.GTP6.E would emit a GTP-U packet from that first fragment
# (its outer chain matches the receiver), so the drop is what turns the
# match into a timeout.
test_frag_outer()
{
	local recv_pid rc=0 recv_rc

	start_recv "$gnb" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" -q "${QFI}" -P "${PDU_TYPE_DL}" \
		-T "${RECV_TIMEOUT_MS}" \
		--pdu-session

	ip netns exec "$srupf" \
		ping -6 -c 1 -s 2000 -M dont -W "${PING_TIMEOUT_SEC}" \
			-I "${SRC6_SRUPF}" "${TRIGGER_PDU}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || recv_rc=$?
	# Expected: timeout (no packet) = exit 2.
	[ "${recv_rc:-0}" -ne 2 ] && rc=1

	log_test "$rc" 0 "End.M.GTP6.E drops a fragmented outer packet"
}

# Test 7: bad attribute values must be rejected at config time.
test_bad_attrs()
{
	local rc=0

	# pdu_type = 2 (parse-time check: only 0 (DL) and 1 (UL) are
	# defined; 2..15 are reserved).
	if ip -n "$srgw" -6 route add 2001:dbf:0::/64 \
		encap seg6mobile action End.M.GTP6.E \
			sr_prefix_len 64 \
			src "${OUTER_SRC}" pdu_type 2 \
		dev veth-n3 2>/dev/null; then
		rc=1
	fi

	# Missing src (required attribute).
	if ip -n "$srgw" -6 route add 2001:dbf:1::/64 \
		encap seg6mobile action End.M.GTP6.E \
			sr_prefix_len 64 \
		dev veth-n3 2>/dev/null; then
		rc=1
	fi

	log_test "$rc" 0 "End.M.GTP6.E rejects bad attribute values at ip route add"
}

# Test 8: udp6_zerocsum_tx -- the emitted GTP-U packet carries a zero
# UDP checksum (RFC 6935).  The receiver asserts uh->check == 0, so a
# checksummed packet fails the match instead of passing vacuously.
test_zerocsum()
{
	local recv_pid rc=0

	start_recv "$gnb" \
		-i veth-n3-gnb -m gtp6-e \
		-s "${OUTER_SRC}" -d "${OUTER_DST}" \
		-t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}" \
		--udp-zero-csum

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" -I "${SRC6_SRUPF}" \
			"${TRIGGER_ZEROCSUM}" \
		>/dev/null 2>&1 || true

	wait "$recv_pid" || rc=$?

	log_test "$rc" 0 "End.M.GTP6.E with udp6_zerocsum_tx emits a zero UDP checksum"
}

# Test 9: the emitted GTP-U packet is routed on the input path, so it
# traverses NF_INET_FORWARD.  Confirm srgw's Ip6OutForwDatagrams counter
# advances -- the previous output-path implementation bypassed it.
test_forward_path()
{
	local before after rc=0

	before=$(read_nstat_counter "$srgw" Ip6OutForwDatagrams)

	ip netns exec "$srupf" \
		ping -6 -c 1 -W "${PING_TIMEOUT_SEC}" -I "${SRC6_SRUPF}" \
			"${TRIGGER_DEFAULT}" \
		>/dev/null 2>&1 || true

	after=$(read_nstat_counter "$srgw" Ip6OutForwDatagrams)
	[ "$((after - before))" -ge 1 ] || rc=1

	log_test "$rc" 0 "End.M.GTP6.E traverses the IPv6 forward path"
}

# H.Encaps on srupf copies the Traffic Class and Hop Limit of the echo
# into the outer header; End.M.GTP6.E copies them into the GTP-U packet,
# whose Hop Limit ip6_forward() then decrements.
test_tclass_hop_limit()
{
	local rc=0

	start_capture "${GTPU_FILTER} and ip6[0:2] & 0x0ff0 = 0x0b80 and \
ip6[7] = 9"
	ip netns exec "$srupf" \
		ping -6 -c 1 -Q 0xb8 -t 10 -W "${PING_TIMEOUT_SEC}" \
			-I "${SRC6_SRUPF}" "${TRIGGER_DEFAULT}" \
		>/dev/null 2>&1 || true
	capture_count
	[ "$cap_count" -eq 1 ] || rc=1

	log_test "$rc" 0 "End.M.GTP6.E copies Traffic Class and Hop Limit"
}

# An SRv6 packet that arrives with Hop Limit 1 cannot be forwarded: its
# source, srupf, gets an ICMPv6 Time Exceeded, and no GTP-U packet leaves
# srgw.
test_hop_limit_1()
{
	local rc=0 errors excds

	errors=$(read_route_errors)
	excds=$(read_nstat_counter "$srupf" Icmp6InTimeExcds)
	start_capture "${GTPU_FILTER}"
	ip netns exec "$srupf" \
		ping -6 -c 1 -t 1 -W "${PING_TIMEOUT_SEC}" \
			-I "${SRC6_SRUPF}" "${TRIGGER_DEFAULT}" \
		>/dev/null 2>&1 || true
	capture_count
	[ "$cap_count" -eq 0 ] || rc=1
	[ "$(read_nstat_counter "$srupf" Icmp6InTimeExcds)" -eq \
	  "$((excds + 1))" ] || rc=1
	[ "$(read_route_errors)" -eq "$((errors + 1))" ] || rc=1

	log_test "$rc" 0 "End.M.GTP6.E sends Time Exceeded for Hop Limit 1"
}

# A GSO T-PDU must be segmented before the encapsulation, so a TCP TSO
# super-frame that exceeds the path MTU is injected on a UE leg and
# forwarded into End.M.GTP6.E via H.Encaps.  The behavior must emit
# GSO_NSEGS GTP-U packets, each with its own GTP-U Length, an intact
# T-PDU and a valid (mandatory) UDP/IPv6 checksum.  Capturing the single
# super-MSS frame at the behavior's ingress guards the case from passing
# vacuously on a pre-segmented flow.
test_gso()
{
	local srupf_mac ing_pid ing_err chk_pid ready before after ing_rc=0 rc=0

	if ! command -v tcpdump >/dev/null; then
		echo "SKIP: tcpdump is required for the GSO case"
		return
	fi

	setup_ns ue
	ip link add veth-ue netns "$ue" \
		type veth peer name veth-ue-srupf netns "$srupf"
	ip -n "$ue"    addr add "${GSO_INNER_SRC}/64" dev veth-ue nodad
	ip -n "$srupf" addr add 2001:db8:aaaa::254/64 dev veth-ue-srupf nodad
	ip -n "$ue"    link set veth-ue up
	ip -n "$srupf" link set veth-ue-srupf up

	ip netns exec "$srupf" sysctl -wq net.ipv6.conf.all.forwarding=1

	# The super-frame must reach End.M.GTP6.E un-segmented, so the sender
	# leg keeps TSO/GSO on; the behavior's egress toward gnb has offloads
	# off (from setup), so the segmentation engine runs there.
	ip netns exec "$srupf" ethtool -K veth-n9 tso on gso on tx on 2>/dev/null

	# End.M.GTP6.E mandates an SRH with Segments Left == 1, so the
	# H.Encaps policy is [SID, final IPv6 destination].
	ip -n "$srupf" -6 route add "${TRIGGER_GSO}/128" \
		encap seg6 mode encap segs "${SID_PDU},${OUTER_DST}" \
			tunsrc "${SRC6_SRUPF}" \
		dev veth-n9

	srupf_mac=$(ip -n "$srupf" link show veth-ue-srupf \
		| awk '/link\/ether/ {print $2}')

	ip netns exec "$srupf" \
		ping -6 -c 1 -W 1 2001:db8:1::2 >/dev/null 2>&1 || true

	before=$(read_nstat_counter "$gnb" Udp6InCsumErrors)

	# Capture the single super-MSS frame at the behavior ingress (the
	# coalesced GSO skb, non-vacuous guard) and check the GTP-U packets it
	# is segmented into at the egress toward gnb.
	ing_err=$(mktemp)
	ip netns exec "$srgw" timeout 3 tcpdump -p -c 1 -i veth-n9-srgw \
		"ip6 src ${SRC6_SRUPF} and greater 1500" \
		>/dev/null 2>"$ing_err" &
	ing_pid=$!
	wait_tcpdump_listening "$ing_err"
	ready=$(mktemp)
	ip netns exec "$gnb" "${GSO_SEND}" -c -i veth-n3-gnb \
		-S "${GSO_SEG}" -n "${GSO_NSEGS}" -r "$ready" >/dev/null 2>&1 &
	chk_pid=$!
	busywait 2000 grep -q ready "$ready" >/dev/null
	rm -f "$ready"

	ip netns exec "$ue" "${GSO_SEND}" \
		-i veth-ue -D "${srupf_mac}" \
		-s "${GSO_INNER_SRC}" -d "${TRIGGER_GSO}" \
		-S "${GSO_SEG}" -n "${GSO_NSEGS}" \
		>/dev/null 2>&1 || true

	wait "$ing_pid" || ing_rc=$?
	rm -f "$ing_err"
	wait "$chk_pid" || rc=1

	after=$(read_nstat_counter "$gnb" Udp6InCsumErrors)

	# ing_rc 0 => a super-MSS frame reached the behavior (non-vacuous);
	# the check => it left as GSO_NSEGS intact G-PDUs; the checksum counter
	# must not move (UDP/IPv6 checksums are mandatory).
	[ "$ing_rc" -eq 0 ] && [ "$before" = "$after" ] || rc=1
	log_test "$rc" 0 "End.M.GTP6.E re-segments a GSO T-PDU into GTP-U packets"
}

main()
{
	check_dependencies
	setup

	test_default
	test_pdu_session
	test_srh_sl0
	test_srh_sl2
	test_srh_absent
	test_srh_malformed
	test_frag_outer
	test_bad_attrs
	test_zerocsum
	test_forward_path
	test_tclass_hop_limit
	test_hop_limit_1
	test_gso

	print_log_test_results
	exit "${ret}"
}

main "$@"
