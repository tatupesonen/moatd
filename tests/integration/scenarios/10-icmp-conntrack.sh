#!/usr/bin/env bash
# ICMP echo conntrack uses the icmp id field to disambiguate request/reply
# from unsolicited inbound requests. The host's outbound ping creates a
# conntrack entry keyed on the host's kernel-picked id; a peer sending its
# own ping uses a different id and must NOT ride that entry.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

moat_cli default deny incoming

# Host-initiated ping: outbound icmp echo creates a conntrack entry with the
# host's icmp id. The matching reply (same id) must pass.
expect_pass "host -> client v4 echo (reply rides conntrack via icmp id)" \
    ping_from_host_v4 1

# Unsolicited inbound from client uses its own kernel's icmp id, distinct
# from the host's. Even though there IS a conntrack entry for the same
# 5-tuple addresses, the icmp ids differ and the reverse lookup must miss.
expect_blocked "client -> host v4 echo (icmp id differs, default deny in)" \
    ping_from_client_v4 1
