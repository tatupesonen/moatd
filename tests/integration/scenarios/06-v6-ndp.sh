#!/usr/bin/env bash
# Default-deny-incoming must NOT break IPv6 neighbor discovery, otherwise
# the host loses v6 connectivity entirely.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

moat_cli default deny incoming

# First: client -> host ping should be blocked. NDP messages (types 133-137)
# must still pass for any v6 to work, but echo request is type 128 -> dropped.
expect_blocked "client -> host v6 echo (deny in, NDP still works)" ping_from_client_v6 1

# Reverse direction: host -> client ping. Outbound + reply via conntrack.
# This implicitly proves NDP works (otherwise the kernel can't resolve the
# client's link-layer address and the ping fails before it leaves).
expect_pass "host -> client v6 echo (NDP + conntrack)" ping_from_host_v6 1
