#!/usr/bin/env bash
# default deny outgoing + explicit allow rules -> egress filtering at TC.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

moat_cli default deny outgoing
moat_cli allow out to "$ADDR_C_V4" port 80 proto tcp

listen_in_client 80
expect_pass    "host -> client:80 (explicit allow out)" nc_to_client_v4 80 2
stop_listener

listen_in_client 81
expect_blocked "host -> client:81 (default deny out)"   nc_to_client_v4 81 2
stop_listener
