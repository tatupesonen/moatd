# Testing

There are two test surfaces.

## Unit tests

```sh
cargo test -p moatd -p moatd-common
```

These cover the rule parser, wire-format conversion, and CIDR parsing.
Fast, no privileges required, run on every CI build.

## Integration tests

Network-namespace based, with real packets:

```sh
cargo build
sudo make integration-test
```

Each scenario:

1. Creates two `ip netns` (`moat-h`, `moat-c`) connected by a veth pair.
2. Starts `moatd` inside `moat-h` with `MOAT_INTERFACES=mvethH`.
3. Configures rules via the `moat` CLI from the root netns (the control
   socket is on the shared filesystem).
4. Drives traffic from `moat-c` using `nc`, `ping`, etc.
5. Asserts pass / blocked.
6. Tears down the netns pair and removes `/etc/moatd/rules.toml`.

Total runtime: ~25 seconds on modern hardware.

## Scenarios

| # | Scenario | Asserts |
| --- | --- | --- |
| 01 | `attach` | XDP + TC programs loaded and attached |
| 02 | `default-allow` | baseline: traffic passes with no rules |
| 03 | `default-deny-in` | `default deny` + `allow 22/tcp` → port 22 reaches, others don't |
| 04 | `default-deny-out` | `default deny outgoing` + explicit allow → matching outbound passes, rest dropped |
| 05 | `conntrack-reply` | TCP reply rides conntrack under `default deny in` |
| 06 | `v6-ndp` | IPv6 NDP works even with `default deny in` |
| 07 | `v6-ingress` | v6-specific port deny actually blocks |
| 08 | `persistence` | rules survive a daemon restart |

## Running a single scenario

```sh
sudo bash tests/integration/scenarios/03-default-deny-in.sh
```

Each scenario is a self-contained bash file that sources
`tests/integration/lib.sh` and traps `cleanup EXIT`, so a failure leaves the
machine clean.

## Requirements

- Linux kernel ≥ 6.1
- root
- `ip`, `nc` (openbsd-netcat), `ping`, `bpftool`

## What's not covered yet

- **Conntrack TTL aging**: 60s of real time is too slow for CI. Could be
  shortened in a debug build to make this testable.
- **Per-interface matching**: the current setup has only one test veth. A
  multi-iface harness would test that `allow on vethA` doesn't match
  `vethB`.
- **ICMP `id` disambiguation**: see [Conntrack](conntrack.md). The current
  LRU conntrack treats ICMP echo request and reply as the same key.
- **`reject` with real RST/unreachable**: phase 5 work; `reject` is
  currently treated as `deny`.
