"""Regression for IPv4 non-initial fragments being misparsed as L4 ports."""

import time

import pytest

from moatlib import packets, ping

pytestmark = pytest.mark.scapy


def test_noninitial_fragment_not_classified_by_payload_ports(topo, moatd):
    c, p = topo.primary.ns_c, topo.primary
    ping(c, p.v4_h)  # warm ARP

    moatd.cli("logging", "on")
    moatd.cli("default", "deny", "incoming")
    moatd.cli("allow", "in", "port", "12345", "proto", "tcp")

    # A non-initial fragment whose payload, if misread as a TCP header, decodes
    # dst port 12345 (allowed). Pre-fix it bypassed; now it has no ports, so it
    # falls to default-deny and the daemon logs a BLOCK.
    packets.send(c, kind="v4frag", iface=p.if_c, src=p.v4_c, dst=p.v4_h, frag_dport=12345)
    time.sleep(1.5)  # the block-log drainer dedupes over a 1s window

    assert "BLOCK" in moatd.log_text(), "fragment was not denied (misclassified by payload bytes)"
