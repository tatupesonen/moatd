# moatd integration tests

Network-namespace integration tests for the moatd firewall, written in Python
(pytest) and managed with [uv](https://docs.astral.sh/uv/). Each test:

1. Creates a fresh host/client netns pair joined by a veth (`Topology`).
2. Runs `moatd` inside the host netns (`Moatd`), driving it via the CLI.
3. Sends real traffic (`nc`/`ping`) or crafted packets (scapy) and asserts
   pass/blocked — by connectivity, by the daemon's BLOCK log, or via `bpftool`.
4. Tears everything down.

The eBPF object is loaded into the **real kernel**, so the verifier and the
data path are exercised for real.

## Running

```sh
cargo build                  # build moatd/moat as your user
make integration-test        # uv sync + sudo pytest (root needed for netns)
```

Or directly:

```sh
cd tests/integration
uv sync
sudo .venv/bin/python -m pytest                 # everything except perf
sudo .venv/bin/python -m pytest -m perf         # perf characterization only
sudo .venv/bin/python -m pytest -m 'not scapy'  # skip crafted-packet tests
sudo .venv/bin/python -m pytest tests/test_cidr.py
```

> If the installed `moatd` service is running it owns
> `/run/moatd/control.sock` and the suite refuses to start. Stop it first:
> `sudo systemctl stop moatd`.

## Across kernel versions (virtme-ng)

`run-vng.sh` boots the suite inside a throwaway VM, exercising the program
against a specific kernel without touching the host:

```sh
./run-vng.sh                       # current host kernel
./run-vng.sh /path/to/bzImage ...  # one or more kernels (a matrix)
```

Needs `vng` (`apt install virtme-ng`) and `/dev/kvm`.

## Requirements

- root (netns); `/dev/kvm` for the vng runner
- tools: `ip`, `nc` (openbsd-netcat), `ping`, `bpftool`, `iperf3` (perf test)
- `uv`; the Python deps (`pytest`, `scapy`) come from `uv sync`

## Markers

- `scapy` — crafts raw packets (IPv6 ext headers, fragments, VLAN tags)
- `perf` — slower, timing-sensitive; opt-in

## Layout

```
tests/integration/
├── pyproject.toml      uv project + pytest config
├── conftest.py         fixtures (topo, moatd) + root/foreign-daemon preflight
├── moatlib/            netns, daemon, traffic, bpf, scapy senders
├── tests/              one file per area
└── run-vng.sh          kernel-matrix runner
```
