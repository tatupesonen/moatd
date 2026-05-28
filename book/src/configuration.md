# Configuration

## Files

| Path | Mode | Purpose |
| --- | --- | --- |
| `/etc/moatd/rules.toml` | 0640 | Persisted rules and default policy. Daemon writes, you can read. |
| `/etc/moatd/applications.d/` | 0750 | App-profile snippets (planned). |
| `/run/moatd/control.sock` | 0660 root:root | Control socket. CLI talks to daemon here. |
| `/var/lib/moatd/` | 0750 | Reserved for future state (e.g. ringbuf cursors). |
| `/sys/fs/bpf/moatd/` | n/a | BPF map pin path (reserved for future use). |

## rules.toml format

```toml
default_in = "allow"
default_out = "allow"
logging_enabled = false

[[rules]]
direction = "in"
action = "allow"
proto = "tcp"
dst_port = "22"

[[rules]]
direction = "in"
action = "allow"
proto = "tcp"
src = "10.0.0.0/8"
dst_port = "443"

[[rules]]
direction = "out"
action = "allow"
proto = "udp"
dst = "8.8.8.8"
dst_port = "53"
```

Fields:

| Field | Type | Default |
| --- | --- | --- |
| `direction` | `"in"` \| `"out"` | required |
| `action` | `"allow"` \| `"deny"` \| `"reject"` | required |
| `iface` | string (interface name, ≤ 15 chars) | none |
| `proto` | `"tcp"` \| `"udp"` \| `"icmp"` \| `"any"` | any |
| `src` | CIDR string (v4 or v6) | any |
| `dst` | CIDR string (v4 or v6) | any |
| `src_port` | `"22"` or `"1000-2000"` | none |
| `dst_port` | same | none |

You shouldn't normally edit this file by hand. Use the CLI; the daemon writes
the file atomically. Hand-edits are picked up on the next daemon restart.

## Environment variables

| Variable | Effect |
| --- | --- |
| `MOAT_INTERFACES=eth0,wg0` | Override interface auto-discovery. The daemon attaches only to the listed interfaces. Useful for testing and constrained deployments. |
| `MOAT_LOG=debug` | Daemon log filter, follows `tracing` env-filter syntax. |

## systemd unit

The bundled `moatd.service` is intentionally hardened:

```ini
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ReadWritePaths=/sys/fs/bpf /run/moatd /var/lib/moatd /etc/moatd
SystemCallFilter=@system-service @network-io bpf
```

The unit also orders itself before `network.target` and after
`network-pre.target` so the firewall is active before any interface comes up.
