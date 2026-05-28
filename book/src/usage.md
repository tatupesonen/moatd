# Usage

All commands except `enable`/`disable` talk to the running daemon over
`/run/moatd/control.sock`. They require root or membership in the `moatd`
group (planned; today the socket is root-only).

## Lifecycle

| Command | What it does |
| --- | --- |
| `moat enable` | `systemctl enable --now moatd` |
| `moat disable` | `systemctl disable --now moatd` |
| `moat status` | print defaults, attached interfaces, rule count |
| `moat ping` | round-trip health check |
| `moat reset` | wipe all rules and restore allow/allow defaults |

## Rules

| Command | Example |
| --- | --- |
| `moat allow <spec>` | `moat allow 22/tcp` |
| `moat deny <spec>` | `moat deny in port 80 proto tcp` |
| `moat reject <spec>` | `moat reject 25/tcp` (treated as drop until phase 5) |
| `moat list` | numbered list of all rules |
| `moat delete N` | delete the 1-indexed rule at position N |

## Default policies

```sh
moat default <allow|deny|reject> <incoming|outgoing>
```

For example:

```sh
moat default deny incoming
moat default allow outgoing
```

`incoming` / `outgoing` (or `in` / `out`) controls which direction's default
changes.

## Logging

```sh
moat logging on
moat logging off
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
