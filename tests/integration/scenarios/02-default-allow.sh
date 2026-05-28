#!/usr/bin/env bash
# Baseline: default allow lets traffic through in both directions.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

# Defaults are allow/allow on fresh install.
listen_in_host 8080
expect_pass "tcp from client -> host:8080 with default allow" nc_to_host_v4 8080
stop_listener

expect_pass "ping host -> client with default allow" ping_from_host_v4 1
