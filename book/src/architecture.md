# Architecture

```
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│   moat (CLI)    │──▶│ /run/moatd/     │──▶│  moatd          │
│  ufw-style cmd  │   │  control.sock   │   │  (Tokio daemon) │
└─────────────────┘   └─────────────────┘   └────────┬────────┘
                                                     │
                                                     ▼
                       ┌──────────────────────────────────────────┐
                       │  BPF maps (held by moatd):               │
                       │    RULES        Array<Rule>        256   │
                       │    DEFAULT_POL  Array<u8>          3     │
                       │    CONFIG       Array<GlobalConfig> 1    │
                       │    CONNTRACK    LruHashMap<...>  64Ki    │
                       └────────┬─────────────────────┬───────────┘
                                │                     │
                        loaded by moatd       attached by moatd
                                │                     │
                                ▼                     ▼
                       ┌────────────────┐    ┌────────────────┐
                       │ moat_ingress   │    │ moat_egress    │
                       │ (XDP)          │    │ (TC clsact)    │
                       └───────┬────────┘    └───────┬────────┘
                               │                     │
       NIC ───── driver ─── XDP ───▶ kernel stack ───▶ TC ─── driver ──▶ NIC
              (inbound)                                            (outbound)
```

## Crates

| Crate | Target | Purpose |
| --- | --- | --- |
| `moatd-common` | host & bpf | Wire-format types (`Rule`, `IpCidr`, `ConnKey`, etc.) shared between user space and the eBPF program. `no_std` by default, with a `user` feature that pulls in `aya::Pod` and the control protocol. |
| `moatd-ebpf` | `bpfel-unknown-none` | The XDP and TC programs. Built via `aya-build`. |
| `moatd` | host | The userspace crate. Produces two binaries: the `moatd` daemon and the `moat` CLI. |

## Packet path

### Ingress (XDP)

1. Bounds-checked parse: Ethernet → IPv4 or IPv6 → TCP/UDP/ICMP.
   Non-IP traffic (ARP, etc.) is passed unchanged.
2. **NDP exemption.** ICMPv6 types 133–137 (router/neighbor solicit/advert,
   redirect) are always allowed. Without this, `default deny incoming`
   would break IPv6 entirely.
3. **Conntrack reverse lookup.** If the packet's reversed 5-tuple matches a
   recent entry inserted by the egress program, `XDP_PASS`. No refresh on
   ingress — only the egress side renews entries. See [Conntrack](conntrack.md).
4. **Rule walk.** Iterate the `RULES` array (capacity 256). First rule with
   all fields matching wins. Returns the rule's action.
5. **Default policy.** If no rule matched, apply `DEFAULT_POLICY[in]`.

### Egress (TC clsact)

1. Same parse as ingress.
2. NDP exemption (pass).
3. Rule walk against direction = `out`.
4. If allow → `TC_ACT_PIPE` (let the packet continue down the pipeline) and
   insert the forward 5-tuple into `CONNTRACK` so the reply can match.
5. If deny → `TC_ACT_SHOT` (drop).

## Why two programs, not one

XDP only sees ingress packets. TC clsact can hook both, but XDP has
significantly lower per-packet cost on inbound traffic because it runs before
`skb` allocation. So:

- XDP for the **hot inbound path**.
- TC egress for **outbound** (XDP doesn't have an egress equivalent on most
  drivers) and **conntrack insertion**.

This split also means rule matching happens twice (once per program), but the
match logic is shared and the verifier inlines aggressively.

## Userspace flow

```
moat CLI                    moatd                       BPF
──────────                  ─────                       ───
parse rule spec   ─json───▶ AddRule(rule)
                            validate iface name
                            append to in-memory list
                            persist rules.toml
                            sync RULES map     ─bpf_map_update──▶ kernel
                  ◀──Ok─── reply
print "rule added"
```

Persistence is atomic: the daemon writes `rules.toml.tmp` and then
`rename(2)`s it over `rules.toml`. The temp file is created with mode 0640 to
avoid a world-readable window.

## What the kernel sees

```sh
$ sudo bpftool prog show name moat_ingress
123: xdp  name moat_ingress  tag ...  gpl
        loaded_at ...  uid 0
        xlated ... jited ...
        map_ids 1,2,3,4

$ sudo bpftool net show
xdp:
mvethH(34) driver id 123
tc:
mvethH(34) tcx/egress moat_egress prog_id 124 ...
```

On kernels with TCX support (6.6+), aya uses `BPF_LINK_TYPE_TCX`. On older
kernels it falls back to classic clsact filters.
