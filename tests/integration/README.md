# moat integration tests

Network-namespace integration tests for the moat firewall. Each scenario:

1. Creates a fresh pair of `ip netns` connected by a veth pair (`moat-h` / `moat-c`).
2. Starts `moatd` inside `moat-h` with `MOAT_INTERFACES=mvethH`.
3. Configures rules via the `moat` CLI.
4. Drives traffic from `moat-c` with `nc` / `ping` and asserts pass / blocked.
5. Tears down the netns pair and removes `/etc/moatd/rules.toml`.

## Running locally

Two steps because `cargo` needs to run as your normal user (the toolchain is
in your `$PATH`, not root's) and the test runner needs root for `ip netns`:

```sh
cargo build
sudo make integration-test
```

Equivalently, without the Makefile:

```sh
cargo build
sudo tests/integration/run.sh
```

Run a single scenario:

```sh
sudo bash tests/integration/scenarios/03-default-deny-in.sh
```

## Requirements

- Linux kernel >= 6.1 (TCX requires 6.6+, falls back to classic clsact otherwise)
- root
- tools: `ip`, `nc` (openbsd-netcat), `ping`, `bpftool`
- moatd + moat built (`cargo build`)

## Layout

```
tests/integration/
├── lib.sh         shared bash helpers
├── run.sh         runner (serial, prints pass/fail per scenario)
└── scenarios/     individual scenarios, sorted by number
```

Each scenario sources `lib.sh`, calls `setup_netns`, `start_moatd`, and uses
`expect_pass` / `expect_blocked` for assertions. `trap cleanup EXIT` ensures
namespaces and the daemon are cleaned up even on failure.

## Notes

- The daemon is run *inside* the netns; the `moat` CLI runs in the root netns
  and talks to the daemon via the shared `/run/moatd/control.sock` (mount
  namespaces are shared between netns).
- `MOAT_INTERFACES=mvethH` makes the daemon attach only to the test veth and
  ignore the host's real NICs.
- Scenarios run serially (each consumes the global socket path and rule file).
