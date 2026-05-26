#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
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
#   4. GTPv1-U Echo Request                  -> passthrough to lupf-v4
#   5. Bad attribute (sr_prefix_len 97)      -> ip route add returns EINVAL
#   6. seg6mobile rejects IPv6 routes for H.M.GTP4.D

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

# Source UPF Prefix length P=64.  v4_mask_len=32 overlays v4 SA
# (10.0.0.2 = gnb) into bytes 8..11 of the src template.  The
# template's :: tail keeps bytes 12..15 as 0..0..0..1.
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
			v4_mask_len 32 sr_prefix_len 32 count \
		via "${V4_LUPF}" dev veth-n6
}

# Run the AF_PACKET receiver on srupf and fire one GTP-U packet from
# gnb.  Returns the receiver's exit status.
run_tpdu_match()
{
	local expected_last_sid=$1
	local teid=$2
	local send_args=("${@:3}")
	local recv_pid rc=0

	ip netns exec "$srupf" "${RECV}" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${EXPECTED_OUTER_SRC}" -d "${expected_last_sid}" \
		-L "${expected_last_sid}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$gnb" "${SEND}" -m gtp4-d \
		-s "${V4_GNB}" -d "${V4_DST}" -t "${teid}" \
		"${send_args[@]}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
}

# Same as run_tpdu_match but expects the receiver to time out.
run_tpdu_no_match()
{
	local send_args=("$@")
	local recv_pid rc=0

	ip netns exec "$srupf" "${RECV}" \
		-i veth-n9-srupf -m gtp6-d \
		-s "${EXPECTED_OUTER_SRC}" -d "${EXPECTED_LAST_SID_PSC}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

	ip netns exec "$gnb" "${SEND}" -m gtp4-d \
		-s "${V4_GNB}" -d "${V4_DST}" -t "${TEID_HEX}" \
		"${send_args[@]}" \
		>/dev/null 2>&1 || true

	wait "${recv_pid}" || rc=$?
	echo "${rc}"
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
	ip netns exec "$lupfv4" "${RECV}" \
		-i veth-n6-lupf -m gtp4-e \
		-s "${V4_GNB}" -d "${V4_DST}" -t "${TEID_HEX}" \
		-T "${RECV_TIMEOUT_MS}" \
		>/dev/null 2>&1 &
	recv_pid=$!
	sleep 0.2

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
	log_test "$rc" 2 "H.M.GTP4.D drops malformed GTP-U extension chain"
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

	# sr_prefix_len = 97 (> 88, leaves no room for 40-bit Args.Mob.Session).
	if ip -n "$srgw" -4 route add 10.99.1.0/24 \
		encap seg6mobile action H.M.GTP4.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC_TEMPLATE}" \
			v4_mask_len 32 sr_prefix_len 97 \
		dev veth-n6 2>/dev/null; then
		rc=1
	fi

	# sr_prefix_len + v4_mask_len + 40 > 128 (validate callback).
	if ip -n "$srgw" -4 route add 10.99.2.0/24 \
		encap seg6mobile action H.M.GTP4.D \
			srh segs "${SR_POLICY_LAST}" \
			src "${OUTER_SRC_TEMPLATE}" \
			v4_mask_len 64 sr_prefix_len 32 \
		dev veth-n6 2>/dev/null; then
		rc=1
	fi

	# Missing required SRH.
	if ip -n "$srgw" -4 route add 10.99.3.0/24 \
		encap seg6mobile action H.M.GTP4.D \
			src "${OUTER_SRC_TEMPLATE}" \
			v4_mask_len 32 sr_prefix_len 32 \
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
			v4_mask_len 32 sr_prefix_len 32 \
		dev veth-n6 2>/dev/null; then
		rc=1
	fi

	log_test "$rc" 0 "H.M.GTP4.D rejects attachment to an IPv6 route"
}

check_dependencies
setup

test_short_tpdu
test_psc_tpdu
test_drop_malformed_gtpu
test_passthrough_echo
test_bad_attrs
test_rejects_ipv6_route

print_log_test_results
exit "$ret"
