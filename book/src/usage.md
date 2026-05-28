# Usage

All commands except `enable`/`disable` talk to the running daemon over
`/run/moatd/control.sock`. They require root or membership in the `moatd`
group (planned; today the socket is root-only).

## Lifecycle

| Command | What it does |
| --- | --- |
| `moatd enable` | `systemctl enable --now moatd` |
| `moatd disable` | `systemctl disable --now moatd` |
| `moatd status` | print defaults, attached interfaces, rule count |
| `moatd ping` | round-trip health check |
| `moatd reset` | wipe all rules and restore allow/allow defaults |

## Rules

| Command | Example |
| --- | --- |
| `moatd allow <spec>` | `moatd allow 22/tcp` |
| `moatd deny <spec>` | `moatd deny in port 80 proto tcp` |
| `moatd reject <spec>` | `moatd reject 25/tcp` (treated as drop until phase 5) |
| `moatd list` | numbered list of all rules |
| `moatd delete N` | delete the 1-indexed rule at position N |

## Default policies

```sh
moatd default <allow|deny|reject> <incoming|outgoing>
```

For example:

```sh
moatd default deny incoming
moatd default allow outgoing
```

`incoming` / `outgoing` (or `in` / `out`) controls which direction's default
changes.

## Logging

```sh
moatd logging on
moatd logging off
```

The eBPF program emits one event per dropped packet to a ringbuf; the daemon
drains it and forwards to journald. The userspace path is in place but the
eBPF emission is a phase-5 task; `logging on` is a no-op for now.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | client-side error (parse error, can't connect to daemon, etc.) |
| non-zero | daemon-reported error; message printed to stderr |
