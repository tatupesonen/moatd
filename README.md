<p align="center">
  <img src="moatd.png" alt="moatd" width="380">
</p>

<p align="center">
  A small, fast host firewall for Linux. eBPF in the kernel, ufw-style CLI in user space.
</p>

<p align="center">
  <a href="https://github.com/tatupesonen/moatd/actions"><img alt="CI" src="https://github.com/tatupesonen/moatd/actions/workflows/ci.yml/badge.svg"></a>
</p>

## What it is

`moatd` is the daemon; `moat` is the CLI. Rules are evaluated in eBPF (XDP for ingress, TC clsact for egress), so dropped traffic never reaches the kernel network stack. Outbound flows are tracked in an LRU conntrack so replies survive `default deny incoming`. Unlike `ufw`, traffic destined for Docker-published ports **is** filtered because XDP runs before Docker's DNAT.

## Requirements

- Linux kernel 6.1 or newer (6.6+ recommended for TCX)
- `bpf-linker` and Rust nightly with `rust-src` to build
- root or `CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON` to load programs

## Install

```sh
git clone git@github.com:tatupesonen/moatd.git
cd moatd
cargo build --release
sudo make install
sudo systemctl daemon-reload
sudo moat enable
```

The systemd unit (`moatd.service`) starts before `network.target`, attaches XDP and TC programs to every non-bridge interface, and exposes a control socket at `/run/moatd/control.sock`.

## Usage

```sh
moat status                                   # show defaults, attached interfaces, rule count
moat allow 22/tcp                             # allow SSH from anywhere
moat allow in on tailscale0 to any port 22    # allow SSH on the tailscale interface only
moat allow out to 8.8.8.8 port 53 proto udp   # allow outbound DNS to a specific resolver
moat deny in port 80 proto tcp                # block inbound HTTP
moat default deny incoming                    # change default policy (replies still pass via conntrack)
moat list                                     # numbered rules
moat delete 2                                 # delete the rule at position 2
moat reset                                    # clear all rules + restore allow-all defaults
moat logging on                               # toggle block-event logging (journald)
```

Rule grammar mirrors `ufw`:

```
moat <allow|deny|reject> [in|out]
                          [on <iface>]
                          [from <cidr>] [port <p|p-p>]
                          [to <cidr>]   [port <p|p-p>]
                          [proto tcp|udp|icmp]
```

Shorthands: `moat allow 22` (bare port → dst 22), `moat allow 53/udp` (port/proto).

## Configuration

| Path | Purpose |
|---|---|
| `/etc/moatd/rules.toml` | Persisted rules and default policy (mode 0640) |
| `/etc/moatd/applications.d/` | App profile snippets (planned, phase 5) |
| `/run/moatd/control.sock` | Daemon control socket (mode 0660) |
| `moatd.service` | systemd unit |

The daemon attaches to every non-loopback, non-bridge interface by default. Override with the `MOAT_INTERFACES` env var (comma-separated allowlist) for testing or constrained deployments.

## Documentation

The full guide lives under [`book/`](book/) and is built with [`mdbook`](https://rust-lang.github.io/mdBook/):

```sh
cargo install mdbook
mdbook serve book
```

Then open <http://localhost:3000>.

## Development

```sh
cargo build                # builds the eBPF program via aya-build
cargo test                 # unit tests
sudo make integration-test # 8 netns-based scenarios
```

CI runs both on every push and PR.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
