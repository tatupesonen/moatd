# Introduction

<p align="center">
  <img src="assets/moatd.png" alt="moatd" width="320">
</p>

`moatd` is a small, fast host firewall for Linux. It does its filtering work in
eBPF (XDP for ingress, TC clsact for egress) and exposes a ufw-style CLI for
configuration.

One binary, two roles:

- **`moatd daemon`** runs the firewall: loads the eBPF programs, owns the BPF
  maps, watches `/run/moatd/control.sock`, persists rules to
  `/etc/moatd/rules.toml`. Invoked by `moatd.service`.
- **`moatd <subcommand>`** is the CLI: it talks to the running daemon over
  the control socket. Commands look like `moatd allow 22/tcp`,
  `moatd default deny incoming`,
  `moatd allow in on tailscale0 to any port 22 proto tcp`.

## Why eBPF

- **Line-rate.** Decisions happen in the NIC driver path before the packet
  enters the kernel network stack. Dropped traffic costs the host almost
  nothing.
- **Pre-NAT.** XDP runs before iptables PREROUTING. That means
  Docker-published ports **are** subject to moatd's rules (unlike `ufw`,
  whose rules sit on chains Docker bypasses). See
  [Docker Behavior](docker.md).
- **No iptables conflicts.** moatd uses entirely separate hooks. You can run
  it alongside (or instead of) nftables/iptables without interference.

## Why not ufw / iptables / nftables

| Concern | ufw / iptables | moatd |
| --- | --- | --- |
| Performance | OK for moderate traffic | line-rate (XDP) |
| Docker ports | bypassed unless you fight it | filtered automatically |
| Configuration UX | ufw-style for ufw, raw rules otherwise | ufw-style |
| Implementation language | C | Rust (kernel) + Rust (user space) |

## Current scope

- IPv4 and IPv6 packet parsing with rule matching
- Default-allow or default-deny per direction (in/out)
- ufw-style rule grammar: action, direction, interface, src/dst CIDR, ports, protocol
- LRU connection tracking so replies survive `default deny incoming`
- TOML persistence across daemon restarts
- IPv6 neighbor discovery (NDP) automatically exempt from `default deny in`

## Not (yet) in scope

- `reject` with synthesized TCP RST / ICMP unreachable (currently treated as
  drop)
- IPv6 extension-header walking (most common cases handled; exotic headers
  fall through with no port match)
- App profiles (`/etc/moatd/applications.d/`)
- Block-event logging to journald (the ringbuf path is reserved but not yet
  wired)
- Netlink link watcher: rules referencing a not-yet-present interface are
  inert until the next daemon restart

Roadmap entries are tracked in the project's issue tracker.
