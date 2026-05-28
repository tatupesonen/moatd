"""Crafted-packet sender, run inside a client netns via the venv python.

Prints a JSON line {"reply": bool}. `reply` is whether a response came back
(for SYN probes: a kernel RST/SYN-ACK means the packet passed the firewall).
"""

from __future__ import annotations

import argparse
import json

from scapy.all import (  # type: ignore
    IP,
    IPv6,
    IPv6ExtHdrHopByHop,
    Dot1Q,
    Ether,
    Raw,
    TCP,
    conf,
    send,
    sendp,
    sr1,
)

conf.verb = 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", required=True, choices=["v4", "v6", "v6hbh", "v4frag", "v4vlan"])
    ap.add_argument("--src", required=True)
    ap.add_argument("--dst", required=True)
    ap.add_argument("--iface", required=True)
    ap.add_argument("--dstmac", default="ff:ff:ff:ff:ff:ff")
    ap.add_argument("--vlan", type=int, default=10)
    ap.add_argument("--dport", type=int, default=80)
    ap.add_argument("--sport", type=int, default=40000)
    ap.add_argument("--frag-dport", type=int, default=12345)
    a = ap.parse_args()

    reply = None
    if a.kind == "v4":
        pkt = IP(src=a.src, dst=a.dst) / TCP(sport=a.sport, dport=a.dport, flags="S")
        reply = sr1(pkt, timeout=2, iface=a.iface)
    elif a.kind == "v6":
        pkt = IPv6(src=a.src, dst=a.dst) / TCP(sport=a.sport, dport=a.dport, flags="S")
        reply = sr1(pkt, timeout=2, iface=a.iface)
    elif a.kind == "v6hbh":
        pkt = (
            IPv6(src=a.src, dst=a.dst)
            / IPv6ExtHdrHopByHop()
            / TCP(sport=a.sport, dport=a.dport, flags="S")
        )
        reply = sr1(pkt, timeout=2, iface=a.iface)
    elif a.kind == "v4frag":
        # A standalone non-initial fragment (offset 64B, proto TCP). Its payload,
        # if misread as a TCP header, decodes dst port == frag_dport. No reply is
        # expected (the kernel can't reassemble a lone fragment); the test checks
        # the firewall's BLOCK log instead.
        payload = b"\x00\x00" + int(a.frag_dport).to_bytes(2, "big") + bytes(24)
        pkt = IP(src=a.src, dst=a.dst, proto=6, frag=8, flags=0) / Raw(load=payload)
        send(pkt, iface=a.iface)
        reply = None
    elif a.kind == "v4vlan":
        # An 802.1Q-tagged frame, sent at L2. XDP on the peer sees the tagged
        # frame; if the parser doesn't skip the tag the inner IP is invisible.
        frame = (
            Ether(dst=a.dstmac)
            / Dot1Q(vlan=a.vlan)
            / IP(src=a.src, dst=a.dst)
            / TCP(sport=a.sport, dport=a.dport, flags="S")
        )
        sendp(frame, iface=a.iface)
        reply = None

    print(json.dumps({"reply": reply is not None}))


if __name__ == "__main__":
    main()
