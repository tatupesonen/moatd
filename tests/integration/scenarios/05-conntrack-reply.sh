#!/usr/bin/env bash
# Under default deny incoming, replies to host-initiated TCP flows still pass
# because the TC egress program inserts the forward 5-tuple into CONNTRACK
# and the XDP ingress matches it in reverse.
#
# TCP is the right test here because it has real port disambiguation; our
# simple LRU conntrack can't tell ICMP echo request from echo reply (no port
# field), so an ICMP test would falsely allow unsolicited inbound echo too.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

moat_cli default deny incoming

ip netns exec "$NS_C" nc -l -p 7777 >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.2

# Host opens TCP to client. The SYN-ACK reply MUST be allowed back in by
# conntrack reverse lookup; otherwise the handshake never completes.
expect_pass "host -> client:7777 (SYN-ACK reply rides conntrack)" \
    nc_to_client_v4 7777 3

stop_listener
