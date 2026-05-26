#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# author: Yuya Kusakabe <yuya.kusakabe@gmail.com>

# Selftest for the SRv6 H.M.GTP4.D headend behavior (RFC 9433).
#
#   +-------+   10.0.0.0/24   +-------+ 2001:db8:2::/64 +-------+
#   |  gnb  | --------------- |  srgw | --------------- | srupf |
#   +-------+    veth-n3      +-------+    veth-n9      +-------+
#                          (H.M.GTP4.D)
#                                |
#                                |   10.10.0.0/24
#                                +----- veth-n6 ------- +--------+
#                                                       | lupf-v4|
#                                                       +--------+
#
# gnb sends an IPv4/UDP/GTPv1-U packet to a destination matched by the
# H.M.GTP4.D route on srgw.  srgw encapsulates it in IPv6 + SRH using
# the configured SR Policy, stamping the legacy IPv4 destination and
# Args.Mob.Session (TEID/QFI) into the last SID (an End.M.GTP4.E SID),
# and forwards toward srupf.
# Non-T-PDU GTP-U messages (Echo Request) fall back to the lwtunnel's
# saved orig_input so a downstream legacy peer (lupf-v4) that owns the
# GTP-U control plane can process them.
#
# Cases exercised:
#   1. Short GTPv1-U T-PDU                   -> SRv6 with stamped SRH[0]
#   2. GTPv1-U + PDU Session (QFI=5)         -> SRv6 with QFI in SRH[0]
#   3. Malformed GTP-U extension chain       -> drop
#   4. Duplicate PDU Session containers       -> drop
#   5. GTPv1-U Echo Request                  -> passthrough to lupf-v4
#   6. Bad attribute (sr_prefix_len 97)      -> ip route add returns EINVAL
#   7. seg6mobile rejects IPv6 routes for H.M.GTP4.D
#   8. End.M.GTP4.E then H.M.GTP4.D, delivered locally with
#      CHECKSUM_COMPLETE                      -> skb->csum still valid
#   9. Wrong UDP checksum                     -> drop; checksummed -> SRv6
#  10. GTP-U Length that disagrees with UDP  -> drop
#  11. PDU Session container of 8 bytes      -> SRv6 with QFI in SRH[0]
#  12. IPv4 TOS                               -> copied to the Traffic Class
#  13. T-PDU with Hop Limit or TTL 1          -> SRv6 with a Hop Limit of
#                                                its own
#  14. IPv4 fragments                         -> drop
#  15. IPv4 Record Route option and an IPv6
#      Router Alert socket on srgw           -> SRv6, not taken by the socket
#  16. MTU                                    -> that of the SRv6 egress
#  17. Several G-PDUs in one UDP GSO packet  -> one SRv6 packet each
#  The drops are also counted as errors.

source lib.sh

readonly RECV_TIMEOUT_MS=2000

# H.M.GTP4.D-attached prefix at srgw.
readonly V4_DST_PFX="10.20.0.0/24"
readonly V4_DST="10.20.0.5"
readonly V4_GNB="10.0.0.2"
readonly V4_SRGW_N3="10.0.0.1"
readonly V4_SRGW_N6="10.10.0.1"
readonly V4_LUPF="10.10.0.5"

readonly SR_POLICY_LAST="2001:db8:3::e"
readonly OUTER_SRC_TEMPLATE="2001:db8:2::1"
readonly SRUPF_LINK_ADDR="2001:db8:2::e"

readonly TEID_HEX="0x123"
readonly QFI=5
readonly PDU_TYPE_DL=0

# Source UPF Prefix length P=64.  The 32-bit inbound IPv4 SA
# (10.0.0.2 = gnb) is overlaid into bytes 8..11 of the src template
# following the H.M.GTP4.D Source UPF Prefix layout; the template's
# tail bytes 12..15 are left untouched (kept as 0..0..0..1), so the
# full outer SA below also verifies that the ignored tail is not
# zeroed.
readonly EXPECTED_OUTER_SRC="2001:db8:2:0:a00:2:0:1"

# End.M.GTP4.E SID built from the SR Policy last segment
# (2001:db8:3::e) by overlaying the IPv4 DA (10.20.0.5 = 0a:14:00:05)
# into bytes 4..7 and Args.Mob.Session into bytes 8..12.
# For TEID=0x123, QFI=0 (short header), Args.Mob.Session =
#   (0 << 58) | (0x123 << 24) = 0x0000_0001_2300_0000, top 40 bits
# stamped left-justified at byte 8: 00 00 00 01 23 ...
# For TEID=0x123, QFI=5 (long header + PDU Session): Args.Mob.Session =
#   (5 << 58) | (0x123 << 24) = 0x1400_0001_2300_0000, top 40 bits
# stamped at byte 8: 14 00 00 01 23 ...
readonly EXPECTED_LAST_SID_SHORT="2001:db8:a14:5:0:1:2300:e"
readonly EXPECTED_LAST_SID_PSC="2001:db8:a14:5:1400:1:2300:e"

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

	if ! ip route help 2>&1 | grep -qF "H.M.GTP4.D"; then
		echo "SKIP: iproute2 lacks H.M.GTP4.D action"
		exit "${ksft_skip}"
	fi
}

setup()
{
	setup_ns gnb srgw srupf lupfv4

	ip -n "$gnb"    link set lo up
	ip -n "$srgw"   link set lo up
	ip -n "$srupf"  link set lo up
	ip -n "$lupfv4" link set lo up

	# gnb <-> srgw (IPv4 ingress).
	ip link add veth-n3 netns "$gnb" \
		type veth peer name veth-n3-srgw netns "$srgw"
	ip -n "$gnb"  addr add "${V4_GNB}/24"      dev veth-n3
	ip -n "$srgw" addr add "${V4_SRGW_N3}/24"  dev veth-n3-srgw
	ip -n "$gnb"  link set veth-n3 up
	ip -n "$srgw" link set veth-n3-srgw up

	# srgw <-> srupf (IPv6 egress carrying the SRv6 encap).
	ip link add veth-n9 netns "$srgw" \
		type veth peer name veth-n9-srupf netns "$srupf"
	ip -n "$srgw"  addr add 2001:db8:2::1/64        dev veth-n9 nodad
	ip -n "$srupf" addr add "${SRUPF_LINK_ADDR}/64" dev veth-n9-srupf nodad
	ip -n "$srgw"  link set veth-n9 up
	ip -n "$srupf" link set veth-n9-srupf up

	# srgw <-> lupf-v4 (IPv4 passthrough for non-T-PDU GTP-U).
	ip link add veth-n6 netns "$srgw" \
		type veth peer name veth-n6-lupf netns "$lupfv4"
	ip -n "$srgw"   addr add "${V4_SRGW_N6}/24" dev veth-n6
	ip -n "$lupfv4" addr add "${V4_LUPF}/24"    dev veth-n6-lupf
	ip -n "$srgw"   link set veth-n6 up
	ip -n "$lupfv4" link set veth-n6-lupf up

	ip netns exec "$srgw" sysctl -wq net.ipv4.ip_forward=1
	ip netns exec "$srgw" sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$srgw" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$srgw" \
		sysctl -wq net.ipv6.conf.veth-n9.seg6_enabled=1
	ip netns exec "$srupf" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$srupf" \
		sysctl -wq net.ipv6.conf.veth-n9-srupf.seg6_enabled=1

	# Disable hardware checksum offload so the software path runs.
	ip netns exec "$gnb"    ethtool -K veth-n3 tx off rx off 2>/dev/null
	ip netns exec "$srgw"   ethtool -K veth-n3-srgw tx off rx off 2>/dev/null
	ip netns exec "$srgw"   ethtool -K veth-n9 tx off rx off 2>/dev/null
	ip netns exec "$srgw"   ethtool -K veth-n6 tx off rx off 2>/dev/null
	ip netns exec "$srupf"  ethtool -K veth-n9-srupf tx off rx off 2>/dev/null
	ip netns exec "$lupfv4" ethtool -K veth-n6-lupf tx off rx off 2>/dev/null

	# Route gnb's traffic toward the H.M.GTP4.D-attached prefix.
	ip -n "$gnb" -4 route add "${V4_DST_PFX}" via "${V4_SRGW_N3}"

	# Reach the SR Policy locator (and any Args.Mob.Session-stamped
	# variant in the same /16) via srupf's link address.
	ip -n "$srgw"  -6 route add 2001:db8::/16 via "${SRUPF_LINK_ADDR}" \
		dev veth-n9
	ip -n "$srupf" -6 route add 2001:db8::/16 dev veth-n9-srupf

	# H.M.GTP4.D on srgw.  The route's via is the legacy IPv4 peer
	# (lupf-v4) so the lwtunnel's saved orig_input forwards non-T-PDU
	# GTP-U toward an existing neighbour, while T-PDU encap drops the
	# original dst and re-routes through the new IPv6 outer DA.
	ip -n "$srgw" -4 route add "${V4_DST_PFX}" \
		encap seg6mobile action H.M.GTP4.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC_TEMPLATE}" \
			v6_src_prefix_len 64 \
			sr_prefix_len 32 count \
		via "${V4_LUPF}" dev veth-n6
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

	start_recv "$srupf" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${EXPECTED_OUTER_SRC}" -d "${expected_last_sid}" \
		-L "${expected_last_sid}" \
		-T "${RECV_TIMEOUT_MS}"

	ip netns exec "$gnb" "${SEND}" -m gtp4-d \
		-s "${V4_GNB}" -d "${V4_DST}" -t "${teid}" \
		"${send_args[@]}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

read_route_errors()
{
	ip -n "$srgw" -s -4 route show "${V4_DST_PFX}" |
		grep -oE 'errors [0-9]+' | grep -oE '[0-9]+'
}

# Same as run_tpdu_match but expects the receiver to time out, and srgw
# to count the packet as an error.
run_tpdu_no_match()
{
	local send_args=("$@")
	local recv_pid errors rc=0

	errors=$(read_route_errors)

	start_recv "$srupf" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${EXPECTED_OUTER_SRC}" -d "${EXPECTED_LAST_SID_PSC}" \
		-T "${RECV_TIMEOUT_MS}"

	ip netns exec "$gnb" "${SEND}" -m gtp4-d \
		-s "${V4_GNB}" -d "${V4_DST}" -t "${TEID_HEX}" \
		"${send_args[@]}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	[ "$(read_route_errors)" -eq "$((errors + 1))" ] || rc=0
	echo "${rc}"
}

# Assert that a T-PDU was dropped from the run_tpdu_no_match receiver
# result: exit 0 means a matching SRv6 packet was wrongly forwarded to
# srupf, or not counted as an error, while 1 (a non-matching arrival) and
# 2 (nothing) both confirm the drop.
log_drop_test()
{
	local rc=$1

	[ "$rc" -ne 0 ] && rc=0 || rc=1
	log_test "$rc" 0 "$2"
}

# Capture on srupf for 3 seconds the SRv6 packets from
# EXPECTED_OUTER_SRC that also match the pcap filter @1, into cap_out,
# once the capture has started.
start_capture()
{
	cap_out=$(mktemp)
	cap_err=$(mktemp)
	ip netns exec "$srupf" timeout 3 tcpdump -p -l -n -i veth-n9-srupf \
		"ip6 src ${EXPECTED_OUTER_SRC} and ip6[6] = 43 and $1" \
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
# many SRv6 packets that also match the pcap filter @1 reach srupf.
count_srv6()
{
	local filter=$1; shift

	start_capture "${filter}"
	ip netns exec "$gnb" "${SEND}" -m gtp4-d \
		-s "${V4_GNB}" -d "${V4_DST}" -t "${TEID_HEX}" "$@" \
		>/dev/null 2>&1
	capture_count
	echo "$cap_count"
}

# Run an AF_PACKET receiver on lupf-v4 to verify a non-T-PDU GTP-U
# message arrives unmodified via orig_input passthrough.  We use the
# gtp4-e mode (IPv4/UDP/GTPv1-U short header, no PDU Session) because
# Echo Request is the only non-T-PDU shape used here.  The receiver's
# TEID check applies, but the message type field is not matched.
run_echo_passthrough_match()
{
	local recv_pid rc=0

	# Listen on lupf-v4's incoming leg, matching just outer SA/DA;
	# the gtp4-e mode rejects non-T-PDU types so we instead rely on
	# the receiver seeing the IPv4 outer with the expected addresses.
	# Run a short tcpdump-like check via gtp4-e and accept exit code
	# 1 (mismatch on type) as success too: the packet did arrive.
	start_recv "$lupfv4" \
		-i veth-n6-lupf -m gtp4-e \
		-s "${V4_GNB}" -d "${V4_DST}" -t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}"

	ip netns exec "$gnb" "${SEND}" -m gtp4-d \
		-s "${V4_GNB}" -d "${V4_DST}" -t "${TEID_HEX}" --echo \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

test_short_tpdu()
{
	local rc

	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_SHORT}" "${TEID_HEX}")
	log_test "$rc" 0 "H.M.GTP4.D stamps Args.Mob.Session from a short T-PDU"
}

test_psc_tpdu()
{
	local rc

	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_PSC}" "${TEID_HEX}" \
		--pdu-session -q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 0 "H.M.GTP4.D propagates QFI via PDU Session"
}

test_drop_malformed_gtpu()
{
	local rc

	rc=$(run_tpdu_no_match --pdu-session --malformed \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_drop_test "$rc" "H.M.GTP4.D drops malformed GTP-U extension chain"
}

# The TEID is only trusted from a datagram whose UDP checksum holds; zero
# means none over IPv4.
test_udp_csum()
{
	local rc

	rc=$(run_tpdu_no_match --bad-csum --pdu-session \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_drop_test "$rc" "H.M.GTP4.D drops a wrong UDP checksum"

	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_PSC}" "${TEID_HEX}" \
		--udp-csum --pdu-session -q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 0 "H.M.GTP4.D accepts a UDP checksum"
}

# The GTP-U Length must cover exactly what follows the GTP-U header.
test_drop_gtp_len()
{
	local rc len

	for len in 0 60000; do
		rc=$(run_tpdu_no_match --gtp-len "$len" --pdu-session \
			-q "${QFI}" -P "${PDU_TYPE_DL}")
		log_drop_test "$rc" "H.M.GTP4.D drops GTP-U Length ${len}"
	done
}

# The PDU Session container can carry optional fields past 4 bytes.
test_long_pdu_session()
{
	local rc

	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_PSC}" "${TEID_HEX}" \
		--pdu-session --ext-len 2 -q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 0 "H.M.GTP4.D reads QFI from an 8-byte container"
}

# The IPv4 TOS, ECN included, becomes the Traffic Class.
test_tclass()
{
	local rc=0

	[ "$(count_srv6 'ip6[0:2] & 0x0ff0 = 0x0b80' --tclass 0xb8)" -eq 1 ] ||
		rc=1
	log_test "$rc" 0 "H.M.GTP4.D copies the TOS"
}

# The SRv6 outer header gets a Hop Limit of its own, whatever the T-PDU
# carries, and leaves srgw with it decremented once.
test_hop_limit()
{
	local rc=0

	[ "$(count_srv6 'ip6[7] = 63' --inner-hlim 1)" -eq 1 ] || rc=1
	log_test "$rc" 0 "H.M.GTP4.D forwards an IPv6 T-PDU with Hop Limit 1"

	rc=0
	[ "$(count_srv6 'ip6[7] = 63' --inner4 --inner-hlim 1)" -eq 1 ] || rc=1
	log_test "$rc" 0 "H.M.GTP4.D forwards an IPv4 T-PDU with TTL 1"
}

# An IPv4 fragment cannot be decapsulated: the first one holds part of the
# T-PDU only, and the payload of a later one is not a G-PDU, whatever it
# looks like.
test_drop_fragment()
{
	local rc

	rc=$(run_tpdu_no_match --frag --pdu-session \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_drop_test "$rc" "H.M.GTP4.D drops a first IPv4 fragment"

	rc=$(run_tpdu_no_match --frag-off 10 --pdu-session \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_drop_test "$rc" "H.M.GTP4.D drops a later IPv4 fragment"
}

# What an IPv4 Record Route option leaves in the control block must not
# be read as IPv6 Router Alert by ip6_forward(), which would hand the SRv6
# packet to the Router Alert socket on srgw instead of forwarding it.
test_stale_ip6cb()
{
	local ra_pid ready rc ra_rc=0

	ready=$(mktemp)
	ip netns exec "$srgw" "${RECV}" -i lo -m ra6 \
		-s "${EXPECTED_OUTER_SRC}" -T 3000 -r "$ready" \
		>/dev/null 2>&1 &
	ra_pid=$!
	busywait 2000 grep -q ready "$ready" >/dev/null
	rm -f "$ready"

	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_PSC}" "${TEID_HEX}" \
		--rr --pdu-session -q "${QFI}" -P "${PDU_TYPE_DL}")
	wait "$ra_pid" || ra_rc=$?
	[ "$ra_rc" -eq 2 ] || rc=1
	log_test "$rc" 0 "H.M.GTP4.D does not read IPCB as IPv6 Router Alert"
}

# The SRv6 packet must fit the MTU of its IPv6 egress, not that of the
# device the IPv4 route points to: with a T-PDU of 1348 bytes, the SRv6
# packet is 1412 bytes long.
test_mtu()
{
	local rc toobig

	ip -n "$srgw" link set veth-n6 mtu 1280
	rc=$(run_tpdu_match "${EXPECTED_LAST_SID_SHORT}" "${TEID_HEX}" \
		--pad 1300)
	log_test "$rc" 0 "H.M.GTP4.D ignores the MTU of the IPv4 route"
	ip -n "$srgw" link set veth-n6 mtu 1500

	rc=0
	ip -n "$srgw" link set veth-n9 mtu 1400
	toobig=$(ip netns exec "$srgw" nstat -az Ip6InTooBigErrors |
		awk '$1 == "Ip6InTooBigErrors" {print $2}')
	[ "$(count_srv6 'greater 0' --pad 1300)" -eq 0 ] || rc=1
	[ "$(ip netns exec "$srgw" nstat -az Ip6InTooBigErrors |
	     awk '$1 == "Ip6InTooBigErrors" {print $2}')" -eq \
	  "$((toobig + 1))" ] || rc=1
	log_test "$rc" 0 "H.M.GTP4.D drops a packet too big for the SRv6 egress"
	ip -n "$srgw" link set veth-n9 mtu 1500
}

# Two PDU Session containers chained in the GTP-U extension header list
# must be dropped: a T-PDU carries at most one.
test_drop_dup_pdu_session()
{
	local rc

	rc=$(run_tpdu_no_match --pdu-session --dup-pdu-session \
		-q "${QFI}" -P "${PDU_TYPE_DL}")
	log_test "$rc" 2 "H.M.GTP4.D drops duplicate PDU Session containers"
}

test_passthrough_echo()
{
	local rc

	rc=$(run_echo_passthrough_match)
	# Receiver returns 1 (type mismatch -- expected T-PDU, saw Echo)
	# but had seen the packet on the wire, confirming passthrough.
	# Exit 2 (timeout, no packet) would mean the encap path
	# wrongly absorbed it.
	[ "$rc" = "1" ] && rc=0
	log_test "$rc" 0 "H.M.GTP4.D passes Echo Request through to the legacy peer"
}

test_bad_attrs()
{
	local rc=0

	# sr_prefix_len = 97 (> 56: leaves no room for the 32-bit IPv4 DA
	# plus the 40-bit Args.Mob.Session).
	if ip -n "$srgw" -4 route add 10.99.1.0/24 \
		encap seg6mobile action H.M.GTP4.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC_TEMPLATE}" \
			v6_src_prefix_len 64 \
			sr_prefix_len 97 \
		dev veth-n6 2>/dev/null; then
		rc=1
	fi

	# Missing required SRH.
	if ip -n "$srgw" -4 route add 10.99.3.0/24 \
		encap seg6mobile action H.M.GTP4.D \
			src "${OUTER_SRC_TEMPLATE}" \
			v6_src_prefix_len 64 \
			sr_prefix_len 32 \
		dev veth-n6 2>/dev/null; then
		rc=1
	fi

	log_test "$rc" 0 "H.M.GTP4.D rejects bad attribute values at ip route add"
}

# H.M.GTP4.D is registered against AF_INET; attempting to attach it to
# an IPv6 route must fail at build_state time.
test_rejects_ipv6_route()
{
	local rc=0

	if ip -n "$srgw" -6 route add 2001:db8:bad::/64 \
		encap seg6mobile action H.M.GTP4.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC_TEMPLATE}" \
			v6_src_prefix_len 64 \
			sr_prefix_len 32 \
		dev veth-n6 2>/dev/null; then
		rc=1
	fi

	log_test "$rc" 0 "H.M.GTP4.D rejects attachment to an IPv6 route"
}

# GRO, or a local UDP_SEGMENT sender, can hand H.M.GTP4.D several G-PDUs
# in one UDP GSO skb; each must leave as its own SRv6 packet.  gso_gnb
# sends GSO_NSEGS G-PDUs in one UDP_SEGMENT send to the H.M.GTP4.D prefix
# on gso_rd, which forwards the SRv6 packets to gso_dn.  There End.DT6
# delivers the UDP datagrams to a closed port: each is counted in
# Udp6NoPorts if its checksum, and so its payload, holds.  The GSO frame
# captured at the behavior ingress keeps the case from passing vacuously
# on packets segmented before reaching H.M.GTP4.D.
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
	ip -n "$gso_gnb" addr add 10.0.0.2/24 dev veth-gnb
	ip -n "$gso_rd"  addr add 10.0.0.1/24 dev veth-rd
	ip -n "$gso_gnb" link set veth-gnb up
	ip -n "$gso_rd"  link set veth-rd up

	ip link add veth-rr netns "$gso_rd" \
		type veth peer name veth-dn netns "$gso_dn"
	ip -n "$gso_rd" addr add 2001:db8:2::1/64 dev veth-rr nodad
	ip -n "$gso_dn" addr add 2001:db8:2::e/64 dev veth-dn nodad
	ip -n "$gso_rd" link set veth-rr up
	ip -n "$gso_dn" link set veth-dn up

	ip netns exec "$gso_rd" sysctl -wq net.ipv4.ip_forward=1
	ip netns exec "$gso_rd" sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$gso_dn" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$gso_dn" sysctl -wq net.ipv6.conf.veth-dn.seg6_enabled=1

	ip -n "$gso_gnb" -4 route add "${V4_DST_PFX}" via 10.0.0.1
	ip -n "$gso_rd" -6 route add 2001:db8::/32 via 2001:db8:2::e dev veth-rr
	ip -n "$gso_rd" -4 route add "${V4_DST_PFX}" \
		encap seg6mobile action H.M.GTP4.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC_TEMPLATE}" \
			v6_src_prefix_len 64 \
			sr_prefix_len 32 count \
		dev veth-rd
	ip -n "$gso_dn" -6 route add 2001:db8:a14::/48 \
		encap seg6local action End.DT6 table 100 dev veth-dn
	ip -n "$gso_dn" -6 route add local 2001:db8:200::/64 dev lo table 100

	# Warm the neighbor caches so the lone GSO packet is not lost to
	# address resolution.
	ip netns exec "$gso_gnb" ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
	ip netns exec "$gso_rd" \
		ping -6 -c 1 -W 1 2001:db8:2::e >/dev/null 2>&1 || true

	ing_err=$(mktemp)
	ip netns exec "$gso_rd" timeout 3 tcpdump -p -c 1 -i veth-rd \
		"ip dst ${V4_DST} and greater 1500" \
		>/dev/null 2>"$ing_err" &
	ing_pid=$!
	wait_tcpdump_listening "$ing_err"

	noports=$(ip netns exec "$gso_dn" nstat -az Udp6NoPorts |
		awk '$1 == "Udp6NoPorts" {print $2}')
	errors=$(ip netns exec "$gso_dn" nstat -az Udp6InCsumErrors |
		awk '$1 == "Udp6InCsumErrors" {print $2}')
	ip netns exec "$gso_gnb" "${GSO_SEND}" -U -A "${V4_DST}" \
		-s "${GSO_INNER_SRC}" -d "${GSO_INNER_DST}" \
		-S "${GSO_SEG}" -n "${GSO_NSEGS}" >/dev/null 2>&1 || rc=1

	wait "$ing_pid" || ing_rc=$?
	rm -f "$ing_err"
	sleep 1

	[ "$ing_rc" -eq 0 ] || rc=1
	[ "$(ip netns exec "$gso_dn" nstat -az Udp6NoPorts |
	     awk '$1 == "Udp6NoPorts" {print $2}')" -eq \
	  "$((noports + GSO_NSEGS))" ] || rc=1
	[ "$(ip netns exec "$gso_dn" nstat -az Udp6InCsumErrors |
	     awk '$1 == "Udp6InCsumErrors" {print $2}')" -eq "$errors" ] || rc=1
	log_test "$rc" 0 "H.M.GTP4.D splits a UDP GSO packet into G-PDUs"
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

# End.M.GTP4.E followed by H.M.GTP4.D on the same node must keep skb->csum
# valid for a CHECKSUM_COMPLETE packet that is then delivered locally.  veth
# does not provide CHECKSUM_COMPLETE, so a tc ct action on the ingress of
# csum_rt computes it in software.  ct can only do that while the UDP header
# is the upper-layer header, so csum_hs sends each datagram through
# End.B6.Encaps (which, unlike H.Encaps, keeps CHECKSUM_COMPLETE).
# End.M.GTP4.E then emits IPv4 GTP-U to the local H.M.GTP4.D prefix, whose
# SR Policy ends at a local End.DT6 SID.  A tc pedit action changes the Flow
# Label of the control datagram after ct without updating skb->csum: UDP
# must count it as a checksum error, or the other case may pass vacuously.
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

	ip netns exec "$csum_rt" sysctl -wq net.ipv4.ip_forward=1
	ip netns exec "$csum_rt" sysctl -wq net.ipv4.conf.all.rp_filter=0
	ip netns exec "$csum_rt" sysctl -wq net.ipv4.conf.veth-rt.rp_filter=0
	ip netns exec "$csum_rt" sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "$csum_rt" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
	ip netns exec "$csum_rt" sysctl -wq net.ipv6.conf.veth-rt.seg6_enabled=1

	# csum_hs: 2001:db8:c5::N goes through the End.B6.Encaps SID
	# 2001:db8:c2::N.
	ip -n "$csum_hs" -6 route add 2001:db8:c2::/64 via 2001:db8:c1::2
	for n in 1 2; do
		ip -n "$csum_hs" -6 route add "2001:db8:c5::${n}/128" \
			encap seg6 mode inline segs "2001:db8:c2::${n}" \
			via 2001:db8:c1::2 dev veth-hs
	done

	# csum_rt: End.B6.Encaps towards the End.M.GTP4.E SID for 10.20.0.5.
	# Its outer source carries the IPv4 source 10.0.0.1 at bit 64.
	ip -n "$csum_rt" sr tunsrc set 2001:db8:c1:0:a00:1::
	for n in 1 2; do
		ip -n "$csum_rt" -6 route add "2001:db8:c2::${n}/128" \
			encap seg6local action End.B6.Encaps \
				srh segs 2001:db8:c3:a14:5:: dev veth-rt
	done
	ip -n "$csum_rt" -6 route add 2001:db8:c3::/48 \
		encap seg6mobile action End.M.GTP4.E \
			v6_src_prefix_len 64 sr_prefix_len 48 dev veth-rt
	ip -n "$csum_rt" -4 route add "${V4_DST_PFX}" \
		encap seg6mobile action H.M.GTP4.D \
			srh segs 2001:db8:c7:: src 2001:db8:c1::3 \
			v6_src_prefix_len 64 sr_prefix_len 48 \
		dev veth-rt
	# End.DT6 delivers the datagram through table 100, where its
	# destination is local.
	ip -n "$csum_rt" -6 route add 2001:db8:c7::/48 \
		encap seg6local action End.DT6 table 100 dev veth-rt
	ip -n "$csum_rt" -6 route add local 2001:db8:c5::/64 dev lo table 100

	if ! tc -n "$csum_rt" qdisc add dev veth-rt clsact 2>/dev/null ||
	   ! tc -n "$csum_rt" filter add dev veth-rt ingress chain 1 prio 1 \
		protocol ipv6 flower dst_ip 2001:db8:c2::2 \
		action pedit ex munge ip6 flow_lbl set 0x12345 2>/dev/null ||
	   ! tc -n "$csum_rt" filter add dev veth-rt ingress prio 1 \
		protocol ipv6 matchall action ct pipe action goto chain 1 \
		2>/dev/null; then
		echo "SKIP: tc ct, flower or pedit not supported"
		return
	fi
	ip netns exec "$csum_rt" sysctl -wq \
		net.netfilter.nf_conntrack_checksum=1

	rc=$(csum_send 2001:db8:c5::2)
	log_test "$rc" 1 "End.M.GTP4.E/H.M.GTP4.D: stale skb->csum detected"
	rc=$(csum_send 2001:db8:c5::1)
	log_test "$rc" 0 "End.M.GTP4.E/H.M.GTP4.D keep skb->csum"
}

check_dependencies
setup

test_short_tpdu
test_psc_tpdu
test_drop_malformed_gtpu
test_drop_dup_pdu_session
test_udp_csum
test_drop_gtp_len
test_long_pdu_session
test_tclass
test_hop_limit
test_drop_fragment
test_stale_ip6cb
test_mtu
test_passthrough_echo
test_bad_attrs
test_rejects_ipv6_route
test_gso
test_csum_complete

print_log_test_results
exit "$ret"
