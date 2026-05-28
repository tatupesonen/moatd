#!/usr/bin/env bash
# `allow in on <iface>` matches that interface only.
#
# Topology: a second veth pair (mvethH2 in NS_H, mvethC2 in a new NS_C2) is
# added next to the standard mvethH/mvethC pair. moatd attaches to both
# host-side ifaces. A rule restricted to `on mvethH` must pass traffic
# arriving on mvethH and reject traffic arriving on mvethH2.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

NS_C2="${NS_C2:-moat-c2}"
IFACE_H2="${IFACE_H2:-mvethH2}"
IFACE_C2="${IFACE_C2:-mvethC2}"
ADDR_H2_V4="${ADDR_H2_V4:-10.98.0.1}"
ADDR_C2_V4="${ADDR_C2_V4:-10.98.0.2}"
PREFIX_V4_2="${PREFIX_V4_2:-24}"

multi_cleanup() {
    ip netns del "$NS_C2" 2>/dev/null || true
    cleanup
}
trap multi_cleanup EXIT

setup_netns

# Second veth pair: NS_H <-> NS_C2 on a different subnet
ip netns add "$NS_C2"
ip link add "$IFACE_H2" type veth peer name "$IFACE_C2"
ip link set "$IFACE_H2" netns "$NS_H"
ip link set "$IFACE_C2" netns "$NS_C2"
ip -n "$NS_H" addr add "$ADDR_H2_V4/$PREFIX_V4_2" dev "$IFACE_H2"
ip -n "$NS_C2" addr add "$ADDR_C2_V4/$PREFIX_V4_2" dev "$IFACE_C2"
ip -n "$NS_C2" link set lo up
ip -n "$NS_H" link set "$IFACE_H2" up
ip -n "$NS_C2" link set "$IFACE_C2" up

ip netns exec "$NS_C2" ping -c 1 -W 1 "$ADDR_H2_V4" >/dev/null 2>&1 \
    || { echo "veth2 sanity ping failed"; exit 1; }

MOAT_IFACES="$IFACE_H,$IFACE_H2" start_moatd

moat_cli default deny incoming
moat_cli allow in on "$IFACE_H" port 7777 proto tcp

ip netns exec "$NS_H" nc -l -p 7777 >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.2

expect_pass "client on $IFACE_H -> host:7777 (rule scoped to $IFACE_H)" \
    ip netns exec "$NS_C" nc -z -w 2 -4 "$ADDR_H_V4" 7777
stop_listener

ip netns exec "$NS_H" nc -l -p 7777 >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.2

expect_blocked "client on $IFACE_H2 -> host:7777 (rule excludes $IFACE_H2)" \
    ip netns exec "$NS_C2" nc -z -w 2 -4 "$ADDR_H2_V4" 7777
stop_listener
