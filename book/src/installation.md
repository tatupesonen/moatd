# Installation

## Requirements

- Linux kernel **6.1 or newer**. 6.6+ is recommended because aya uses TCX
  (link-based TC attach) instead of classic clsact when available.
- `nf_conntrack` is **not** required. moatd ships its own LRU conntrack.
- For building from source:
    - Rust stable
    - Rust nightly with `rust-src` (for the BPF target)
    - `bpf-linker` (`cargo install bpf-linker`)
- To run:
    - root, or the equivalent capability set:
      `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`.

## Build from source

```sh
git clone git@github.com:tatupesonen/moatd.git
cd moatd
cargo build --release
```

The first build downloads dependencies and compiles the eBPF program via
`aya-build`. Subsequent builds reuse the cache and finish in seconds.

## Install

The provided `Makefile` lays out files following the FHS:

```sh
sudo make install
```

This copies:

| From | To | Purpose |
| --- | --- | --- |
| `target/release/moatd` | `/usr/local/sbin/moatd` | daemon |
| `target/release/moat` | `/usr/local/bin/moat` | CLI |
| `dist/moatd.service` | `/etc/systemd/system/moatd.service` | systemd unit |
| `dist/modules-load.d/moatd.conf` | `/etc/modules-load.d/moatd.conf` | (currently empty stub) |

Then reload systemd and enable the firewall:

```sh
sudo systemctl daemon-reload
sudo moat enable    # equivalent to: systemctl enable --now moatd
```

## Verify

```sh
moat ping     # → pong
moat status   # active, default allow, attached interfaces
sudo bpftool net show
```

The last command should show `moat_ingress` (XDP) and `moat_egress` (TC) on
each interface moatd attached to.

## Uninstall

```sh
sudo moat disable
sudo make uninstall
sudo rm -rf /etc/moatd /var/lib/moatd /run/moatd
```

## Packaging

Native package builds (`cargo-deb`, `cargo-generate-rpm`) are planned but not
yet wired up. Until then, `make install` is the supported path.
