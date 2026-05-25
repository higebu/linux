#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# author: Yuya Kusakabe <yuya.kusakabe@gmail.com>

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
#   9. End.M.GTP6.E then End.M.GTP6.D, delivered locally with
#      CHECKSUM_COMPLETE                      -> skb->csum still valid
#  10. Wrong UDP checksum                     -> drop; zero checksum -> SRv6
#  11. GTP-U Length that disagrees with UDP  -> drop
#  12. PDU Session container of 8 bytes      -> SRv6 with QFI in SRH[0]
#  13. Outer Traffic Class                    -> copied to the SRv6 outer
#  14. T-PDU with Hop Limit or TTL 1          -> SRv6 with a Hop Limit of
#                                                its own
#  15. No Next Header, fragmented ICMPv6     -> passthrough to lupf
#  16. Several G-PDUs in one UDP GSO packet  -> one SRv6 packet each
#  The drops are also counted as errors.

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

# GSO case: GSO_NSEGS G-PDUs, each a UDP datagram of GSO_SEG bytes from
# GSO_INNER_SRC to GSO_INNER_DST, sent as one UDP GSO packet.
readonly GSO_SEG=200
readonly GSO_NSEGS=8
readonly GSO_INNER_SRC="2001:db8:aaaa::1"
readonly GSO_INNER_DST="2001:db8:200::2"

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
	start_recv "$srupf" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${OUTER_SRC}" -d "${expected_last_sid}" \
		-L "${expected_last_sid}" \
		-T "${RECV_TIMEOUT_MS}"

	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${SID}" -t "${teid}" \
		"${send_args[@]}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

read_route_counter()
{
	ip -n "$srgw" -s -6 route show 2001:db8:f::/64 |
		grep -oE "$1 [0-9]+" | grep -oE '[0-9]+'
}

# Same as run_tpdu_match but expects the receiver to time out (the
# packet must not reach srupf), and srgw to count it as an error.
run_tpdu_no_match()
{
	local send_args=("$@")
	local recv_pid errors rc=0

	errors=$(read_route_counter errors)

	start_recv "$srupf" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${OUTER_SRC}" -d "${EXPECTED_LAST_SID_PSC}" \
		-T "${RECV_TIMEOUT_MS}"

	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${SID}" -t "${TEID_HEX}" \
		"${send_args[@]}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	[ "$(read_route_counter errors)" -eq "$((errors + 1))" ] || rc=0
	echo "${rc}"
}

# Assert that a T-PDU was dropped from the run_tpdu_no_match receiver
# result: exit 0 means a matching SRv6 packet was wrongly forwarded to
# srupf, or not counted as an error, while 1 (a non-matching arrival) and
# 2 (nothing) both confirm the drop.  srgw's Neighbor Discovery uses
# 2001:db8:2::1, the same address as the SRv6 outer source, so a bare
# timeout (exit 2) is not guaranteed; treat any non-match as a successful
# drop.
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

	start_recv "$lupf" \
		-i veth-n6-lupf -m gtp6-passthru \
		-s 2001:db8:1::2 -d "${SID}" \
		-T "${RECV_TIMEOUT_MS}"

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
	log_drop_test "$rc" "End.M.GTP6.D drops malformed GTP-U extension chain"
}

# RFC 9433: an SRH with Segments Left != 0 is not for this
# SID to act on.
test_drop_active_srh()
{
	local rc

	rc=$(run_tpdu_no_match --active-srh --pdu-session \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_drop_test "$rc" "End.M.GTP6.D drops Segments Left 1"
}

# The TEID is only trusted from a datagram whose UDP checksum holds.  A
# zero checksum is accepted, as the gtp driver accepts it (RFC 6936).
test_udp_csum()
{
	local rc

	rc=$(run_tpdu_no_match --bad-csum --pdu-session \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_drop_test "$rc" "End.M.GTP6.D drops a wrong UDP checksum"

	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_PSC}" "${TEID_HEX}" \
		--zero-csum --pdu-session -q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 0 "End.M.GTP6.D accepts a zero UDP checksum"
}

# The GTP-U Length must cover exactly what follows the GTP-U header.
test_drop_gtp_len()
{
	local rc len

	for len in 0 60000; do
		rc=$(run_tpdu_no_match --gtp-len "$len" --pdu-session \
			-q "${QFI}" -P "${PDU_TYPE_DL}")
		log_drop_test "$rc" "End.M.GTP6.D drops GTP-U Length ${len}"
	done
}

# The PDU Session container can carry optional fields past 4 bytes.
test_long_pdu_session()
{
	local rc

	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_PSC}" "${TEID_HEX}" \
		--pdu-session --ext-len 2 -q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 0 "End.M.GTP6.D reads QFI from an 8-byte container"
}

# Capture on @2 in @1 for 3 seconds with the pcap filter @3 into cap_out,
# once the capture has started.
start_capture()
{
	cap_out=$(mktemp)
	cap_err=$(mktemp)
	ip netns exec "$1" timeout 3 tcpdump -p -l -n -i "$2" "$3" \
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

# Send one T-PDU with the srv6_mobile_send options @2... and print how
# many SRv6 packets from OUTER_SRC that also match the pcap filter @1
# reach srupf.
count_srv6()
{
	local filter=$1; shift

	start_capture "$srupf" veth-n9-srupf \
		"ip6 src ${OUTER_SRC} and ip6[6] = 43 and ${filter}"
	ip netns exec "$gnb" "${SEND}" -m gtp6-d \
		-s 2001:db8:1::2 -d "${SID}" -t "${TEID_HEX}" "$@" \
		>/dev/null 2>&1
	capture_count
	echo "$cap_count"
}

# The outer Traffic Class of the GTP-U packet, ECN included, carries over
# to the SRv6 outer header.
test_tclass()
{
	local rc=0

	[ "$(count_srv6 'ip6[0:2] & 0x0ff0 = 0x0b80' --tclass 0xb8)" -eq 1 ] ||
		rc=1
	log_test "$rc" 0 "End.M.GTP6.D copies the Traffic Class"
}

# The SRv6 outer header gets a Hop Limit of its own, whatever the T-PDU
# carries, and leaves srgw with it decremented once.
test_hop_limit()
{
	local rc=0

	[ "$(count_srv6 'ip6[7] = 63' --inner-hlim 1)" -eq 1 ] || rc=1
	log_test "$rc" 0 "End.M.GTP6.D forwards an IPv6 T-PDU with Hop Limit 1"

	rc=0
	[ "$(count_srv6 'ip6[7] = 63' --inner4 --inner-hlim 1)" -eq 1 ] || rc=1
	log_test "$rc" 0 "End.M.GTP6.D forwards an IPv4 T-PDU with TTL 1"
}

# A packet without a UDP header is processed as for any upper-layer
# header, here by forwarding it toward lupf: one with No Next Header, and
# both fragments of an ICMPv6 echo.
test_passthrough_non_udp()
{
	local rc=0

	start_capture "$lupf" veth-n6-lupf "ip6 dst ${SID} and ip6[6] = 59"
	ip netns exec "$gnb" "${SEND}" -m end-map \
		-s 2001:db8:1::2 -d "${SID}" --no-next-header \
		>/dev/null 2>&1 || rc=1
	capture_count
	[ "$cap_count" -eq 1 ] || rc=1
	log_test "$rc" 0 "End.M.GTP6.D passes No Next Header through"

	rc=0
	start_capture "$lupf" veth-n6-lupf "ip6 dst ${SID} and ip6[6] = 44"
	ip netns exec "$gnb" ping -6 -c 1 -s 2000 -M dont -W 1 "${SID}" \
		>/dev/null 2>&1
	capture_count
	[ "$cap_count" -eq 2 ] || rc=1
	log_test "$rc" 0 "End.M.GTP6.D passes a fragmented ICMPv6 echo through"
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

# GRO, or a local UDP_SEGMENT sender, can hand End.M.GTP6.D several G-PDUs
# in one UDP GSO skb; each must leave as its own SRv6 packet.  gso_gnb
# sends GSO_NSEGS G-PDUs in one UDP_SEGMENT send to the End.M.GTP6.D SID on
# gso_rd, which forwards the SRv6 packets to gso_dn.  There End.DT6
# delivers the UDP datagrams to a closed port: each is counted in
# Udp6NoPorts if its checksum, and so its payload, holds.  The GSO frame
# captured at the behavior ingress keeps the case from passing vacuously
# on packets segmented before reaching End.M.GTP6.D.
test_gso()
{
	local ing_pid ing_err noports errors ing_rc=0 rc=0

	if ! command -v tcpdump >/dev/null; then
		echo "SKIP: tcpdump is required for the GSO case"
		return
	fi

	setup_ns gso_gnb gso_rd gso_dn

	ip link add veth-gnb netns "$gso_gnb" \
		type veth peer name veth-rd netns "$gso_rd"
	ip -n "$gso_gnb" addr add 2001:db8:1::2/64 dev veth-gnb nodad
	ip -n "$gso_rd"  addr add 2001:db8:1::1/64 dev veth-rd nodad
	ip -n "$gso_gnb" link set veth-gnb up
	ip -n "$gso_rd"  link set veth-rd up

	# The link address is distinct from the End.M.GTP6.D outer source
	# (OUTER_SRC), so the behavior's own ND is not mistaken for its
	# emitted SRv6.
	ip link add veth-rr netns "$gso_rd" \
		type veth peer name veth-dn netns "$gso_dn"
	ip -n "$gso_rd" addr add 2001:db8:2::100/64 dev veth-rr nodad
	ip -n "$gso_dn" addr add 2001:db8:2::e/64   dev veth-dn nodad
	ip -n "$gso_rd" link set veth-rr up
	ip -n "$gso_dn" link set veth-dn up

	ip netns exec "$gso_rd" sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$gso_rd" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$gso_rd" sysctl -wq net.ipv6.conf.veth-rd.seg6_enabled=1
	ip netns exec "$gso_dn" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$gso_dn" sysctl -wq net.ipv6.conf.veth-dn.seg6_enabled=1

	ip -n "$gso_gnb" -6 route add 2001:db8:f::/64 via 2001:db8:1::1
	ip -n "$gso_rd" -6 route add 2001:db8:3::/64 via 2001:db8:2::e \
		dev veth-rr
	ip -n "$gso_rd" -6 route add 2001:db8:f::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC}" sr_prefix_len 64 count \
		dev veth-rd
	ip -n "$gso_dn" -6 route add 2001:db8:3::/64 \
		encap seg6local action End.DT6 table 100 dev veth-dn
	ip -n "$gso_dn" -6 route add local 2001:db8:200::/64 dev lo table 100

	# Warm the neighbor caches so the lone GSO packet is not lost to
	# address resolution.
	ip netns exec "$gso_gnb" \
		ping -6 -c 1 -W 1 2001:db8:1::1 >/dev/null 2>&1 || true
	ip netns exec "$gso_rd" \
		ping -6 -c 1 -W 1 2001:db8:2::e >/dev/null 2>&1 || true

	ing_err=$(mktemp)
	ip netns exec "$gso_rd" timeout 3 tcpdump -p -c 1 -i veth-rd \
		"ip6 dst ${SID} and greater 1500" \
		>/dev/null 2>"$ing_err" &
	ing_pid=$!
	wait_tcpdump_listening "$ing_err"

	noports=$(read_nstat_counter "$gso_dn" Udp6NoPorts)
	errors=$(read_nstat_counter "$gso_dn" Udp6InCsumErrors)
	ip netns exec "$gso_gnb" "${GSO_SEND}" -U -A "${SID}" \
		-s "${GSO_INNER_SRC}" -d "${GSO_INNER_DST}" \
		-S "${GSO_SEG}" -n "${GSO_NSEGS}" >/dev/null 2>&1 || rc=1

	wait "$ing_pid" || ing_rc=$?
	rm -f "$ing_err"
	busywait 2000 until_counter_is ">= $((noports + GSO_NSEGS))" \
		read_nstat_counter "$gso_dn" Udp6NoPorts >/dev/null

	[ "$ing_rc" -eq 0 ] || rc=1
	[ "$(read_nstat_counter "$gso_dn" Udp6NoPorts)" -eq \
	  "$((noports + GSO_NSEGS))" ] || rc=1
	[ "$(read_nstat_counter "$gso_dn" Udp6InCsumErrors)" -eq "$errors" ] ||
		rc=1
	log_test "$rc" 0 "End.M.GTP6.D splits a UDP GSO packet into G-PDUs"
}

csum_udp6_counter()
{
	ip netns exec "$csum_rt" awk -v k="$1" '$1 == k { print $2 }' \
		/proc/net/snmp6
}

csum_counted()
{
	[ "$(( $(csum_udp6_counter Udp6InCsumErrors) +
	       $(csum_udp6_counter Udp6NoPorts) ))" -gt "$1" ]
}

# Send one UDP datagram from csum_hs to @1, and print 0 if csum_rt delivers
# it to UDP, 1 if UDP counts it as a checksum error, and 2 if it is lost.
# The datagram is longer than 76 bytes: for a shorter one, UDP computes the
# checksum again from the data and ignores a wrong skb->csum.
csum_send()
{
	local dst=$1
	local errors noports

	errors=$(csum_udp6_counter Udp6InCsumErrors)
	noports=$(csum_udp6_counter Udp6NoPorts)
	ip netns exec "$csum_hs" bash -c \
		"printf '%0200d' 0 > /dev/udp/${dst}/9" 2>/dev/null
	busywait 2000 csum_counted "$((errors + noports))"

	if [ "$(csum_udp6_counter Udp6InCsumErrors)" -ne "$errors" ]; then
		echo 1
	elif [ "$(csum_udp6_counter Udp6NoPorts)" -ne "$noports" ]; then
		echo 0
	else
		echo 2
	fi
}

# End.M.GTP6.E followed by End.M.GTP6.D on the same node must keep
# skb->csum valid for a CHECKSUM_COMPLETE packet that is then delivered
# locally.  veth does not provide CHECKSUM_COMPLETE, so a tc ct action on
# the ingress of csum_rt computes it in software.  ct can only do that
# while the UDP header is the upper-layer header, so csum_hs sends each
# datagram through End.B6.Encaps (which, unlike H.Encaps, keeps
# CHECKSUM_COMPLETE).  End.M.GTP6.E then emits GTP-U to the local
# End.M.GTP6.D SID, whose SR Policy ends at a local End.DT6 SID.  The
# control datagram goes the udp6_zerocsum_tx way, but a tc pedit action
# changes its Flow Label after ct without updating skb->csum: UDP must
# count it as a checksum error, or the other cases may pass vacuously.
test_csum_complete()
{
	local rc

	if ! command -v tc >/dev/null; then
		echo "SKIP: tc is required for the CHECKSUM_COMPLETE cases"
		return
	fi

	setup_ns csum_hs csum_rt

	ip link add veth-hs netns "$csum_hs" \
		type veth peer name veth-rt netns "$csum_rt"
	ip -n "$csum_hs" addr add 2001:db8:c1::1/64 dev veth-hs nodad
	ip -n "$csum_rt" addr add 2001:db8:c1::2/64 dev veth-rt nodad
	ip -n "$csum_hs" link set veth-hs up
	ip -n "$csum_rt" link set veth-rt up
	# ct computes skb->csum only from a checksum that csum_hs computed
	ip netns exec "$csum_hs" ethtool -K veth-hs tx off >/dev/null 2>&1

	ip netns exec "$csum_rt" sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$csum_rt" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$csum_rt" sysctl -wq net.ipv6.conf.veth-rt.seg6_enabled=1

	# csum_hs: 2001:db8:c5::N goes through the End.B6.Encaps SID
	# 2001:db8:c2::N.
	ip -n "$csum_hs" -6 route add 2001:db8:c2::/64 via 2001:db8:c1::2
	for n in 1 2 3; do
		ip -n "$csum_hs" -6 route add "2001:db8:c5::${n}/128" \
			encap seg6 mode inline segs "2001:db8:c2::${n}" \
			via 2001:db8:c1::2 dev veth-hs
	done

	# csum_rt: End.B6.Encaps towards an End.M.GTP6.E SID, with
	# udp6_zerocsum_tx (2001:db8:c3::/64) or without (2001:db8:c4::/64),
	# then to the End.M.GTP6.D SID.
	ip -n "$csum_rt" -6 route add 2001:db8:c2::1/128 \
		encap seg6local action End.B6.Encaps \
			srh segs 2001:db8:c3::,2001:db8:c6:: dev veth-rt
	ip -n "$csum_rt" -6 route add 2001:db8:c2::2/128 \
		encap seg6local action End.B6.Encaps \
			srh segs 2001:db8:c4::,2001:db8:c6:: dev veth-rt
	ip -n "$csum_rt" -6 route add 2001:db8:c2::3/128 \
		encap seg6local action End.B6.Encaps \
			srh segs 2001:db8:c3::,2001:db8:c6:: dev veth-rt
	ip -n "$csum_rt" -6 route add 2001:db8:c3::/64 \
		encap seg6mobile action End.M.GTP6.E \
			sr_prefix_len 64 src 2001:db8:c1::3 udp6_zerocsum_tx \
		dev veth-rt
	ip -n "$csum_rt" -6 route add 2001:db8:c4::/64 \
		encap seg6mobile action End.M.GTP6.E \
			sr_prefix_len 64 src 2001:db8:c1::3 dev veth-rt
	ip -n "$csum_rt" -6 route add 2001:db8:c6::/64 \
		encap seg6mobile action End.M.GTP6.D \
			srh segs 2001:db8:c7:: src 2001:db8:c1::4 \
			sr_prefix_len 64 dev veth-rt
	# End.DT6 delivers the datagram through table 100, where its
	# destination is local.
	ip -n "$csum_rt" -6 route add 2001:db8:c7::/64 \
		encap seg6local action End.DT6 table 100 dev veth-rt
	ip -n "$csum_rt" -6 route add local 2001:db8:c5::/64 dev lo table 100

	if ! tc -n "$csum_rt" qdisc add dev veth-rt clsact 2>/dev/null ||
	   ! tc -n "$csum_rt" filter add dev veth-rt ingress chain 1 prio 1 \
		protocol ipv6 flower dst_ip 2001:db8:c2::3 \
		action pedit ex munge ip6 flow_lbl set 0x12345 2>/dev/null ||
	   ! tc -n "$csum_rt" filter add dev veth-rt ingress prio 1 \
		protocol ipv6 matchall action ct pipe action goto chain 1 \
		2>/dev/null; then
		echo "SKIP: tc ct, flower or pedit not supported"
		return
	fi
	ip netns exec "$csum_rt" sysctl -wq \
		net.netfilter.nf_conntrack_checksum=1

	rc=$(csum_send 2001:db8:c5::3)
	log_test "$rc" 1 "End.M.GTP6.E/D: a stale skb->csum is detected"
	rc=$(csum_send 2001:db8:c5::1)
	log_test "$rc" 0 "End.M.GTP6.E/D keep skb->csum, udp6_zerocsum_tx"
	rc=$(csum_send 2001:db8:c5::2)
	log_test "$rc" 0 "End.M.GTP6.E/D keep skb->csum, UDP checksum"
}

check_dependencies
setup

test_short_tpdu
test_psc_tpdu
test_drop_malformed_gtpu
test_drop_frag_outer
test_drop_dup_pdu_session
test_drop_active_srh
test_udp_csum
test_drop_gtp_len
test_long_pdu_session
test_tclass
test_hop_limit
test_passthrough_echo
test_passthrough_non_udp
test_bad_attrs
test_gso
test_csum_complete

print_log_test_results
exit "$ret"
