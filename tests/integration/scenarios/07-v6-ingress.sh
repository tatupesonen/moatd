#!/usr/bin/env bash
# v6 ingress rule matches and a v6-specific deny actually blocks.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

# Sanity: with default allow, v6 reaches.
listen_in_host_v6 8080
expect_pass "v6 client -> host:8080 default allow" nc_to_host_v6 8080 2
stop_listener

# Block port 80 specifically.
moat_cli deny in port 80 proto tcp
listen_in_host_v6 80
expect_blocked "v6 client -> host:80 with deny rule" nc_to_host_v6 80 2
stop_listener

# Other ports still open.
listen_in_host_v6 8081
expect_pass "v6 client -> host:8081 still allowed" nc_to_host_v6 8081 2
stop_listener
