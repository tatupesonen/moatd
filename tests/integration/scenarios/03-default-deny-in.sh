#!/usr/bin/env bash
# default deny incoming + allow 22/tcp -> only port 22 reaches the host.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

moat_cli default deny incoming
moat_cli allow 22/tcp

listen_in_host 22
expect_pass    "client -> host:22 (allow rule)"    nc_to_host_v4 22 2
stop_listener

listen_in_host 8080
expect_blocked "client -> host:8080 (no rule, default deny)" nc_to_host_v4 8080 2
stop_listener
