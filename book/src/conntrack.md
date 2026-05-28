# Conntrack

moatd ships its own LRU connection tracker so reply traffic survives
`default deny incoming` without you having to add explicit allow rules for
every possible reply tuple.

## Why not netfilter conntrack

The "right" answer for the long term is the kernel's own `nf_conntrack`,
reached via the BPF kfuncs `bpf_xdp_ct_lookup` / `bpf_skb_ct_lookup`
(available on Linux 5.19+). It does real TCP state tracking and shares the
table with iptables / IPVS.

That path needs ergonomic kfunc declarations in `aya-ebpf`, which the
crates.io release of aya doesn't yet have. Until that lands, we run an LRU
hash conntrack ourselves. It's coarser (no per-protocol state machine) but
sufficient for "let replies through".

## Implementation

```rust
// 40-byte ConnKey, in moatd-common
#[repr(C)]
pub struct ConnKey {
    pub proto: u8,                  // PROTO_TCP / PROTO_UDP / PROTO_ICMP / PROTO_ICMPV6
    pub family: u8,                 // FAMILY_V4 (4) or FAMILY_V6 (6)
    pub _pad: [u8; 2],
    pub src_addr: [u8; 16],         // v4 packed into the first 4 bytes
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

#[map]
static CONNTRACK: LruHashMap<ConnKey, ConnVal> =
    LruHashMap::with_max_entries(65_536, 0);
```

`ConnVal` carries `last_seen_ns` only. Capacity is 64Ki entries; LRU eviction
is automatic.

## How entries flow

```
1. Host opens outbound:    src=H sport=P_h dst=R dport=P_r
   TC egress inserts CONNTRACK[(proto, H, R, P_h, P_r)] = now

2. Remote sends reply:     src=R sport=P_r dst=H dport=P_h
   XDP ingress reverses:   (proto, H, R, P_h, P_r)
                                     │
                                     ▼
                           CONNTRACK match → XDP_PASS
```

## TTL and refresh

- Entries live for `CONNTRACK_TTL_NS` = **60 seconds** after their last
  refresh.
- **Only egress refreshes.** Originally we refreshed on every conntrack
  ingress hit too, but that lets a spoofed reply (especially for UDP/ICMP,
  which have no handshake) keep an entry alive indefinitely. With egress-only
  refresh, the entry ages out 60 s after the last legitimate outbound packet.

## Known limitations

### ICMP has no port disambiguation

Our key uses ports to distinguish "egress with sport=X" from "spoofed inbound
with sport=X". ICMP has no ports — our `parse_l4` sets both to 0 for ICMP and
ICMPv6. As a result:

- A host-initiated `ping` to a remote creates a conntrack entry.
- A spoofed inbound echo *request* from the same remote, in the same 60 s
  window, will match the reverse key and be allowed.

For ICMP this is rarely exploitable in practice (a spoofed echo request gets
a normal echo reply at most), but it's worth knowing. Real-conntrack uses the
ICMP `id` field for disambiguation; we'd need to fold that into `ConnKey`.

### TCP state isn't tracked

We don't track SYN / SYN-ACK / ACK / FIN. We just refresh on each outbound
packet of the flow. The practical effect: a TCP flow that goes silent for
> 60 s without either side sending is treated as terminated and incoming
replies are blocked. Most real-world flows have keepalives that prevent
this.

### Long one-way receive streams

A receive-mostly UDP stream (e.g. RTP without RTCP) needs the *receiving*
host to also send packets at least every 60 s to keep the conntrack entry
alive. The fix is the same as TCP keepalives: applications send something
back. RTP with RTCP, QUIC with ACKs, etc. handle this naturally.

## How to inspect live

```sh
sudo bpftool map dump name CONNTRACK | head
```

Each entry is 40 bytes of key plus 8 bytes of value. The first byte of the
key is the protocol (`06` for TCP, `11` for UDP, `01` for ICMP, `3a` for
ICMPv6); the second byte is the family (`04` or `06`).
