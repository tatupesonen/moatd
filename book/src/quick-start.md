# Quick Start

This is a five-minute walk-through. Assumes you've already
[installed](installation.md) moatd.

## 1. Enable

```sh
sudo moatd enable
```

This calls `systemctl enable --now moatd`. The daemon attaches XDP + TC
programs to every non-loopback, non-bridge interface, listens on the control
socket, and loads `/etc/moatd/rules.toml` if it exists.

Fresh defaults are **allow incoming, allow outgoing** so the firewall starts
as a no-op.

## 2. Look around

```sh
moatd status
```

```
Status:      active
Schema:      v1
Default in:  Allow
Default out: Allow
Logging:     off
Rules:       0
Interfaces:
  enp0s3
  tailscale0
```

## 3. Allow specific services

```sh
sudo moatd allow 22/tcp
sudo moatd allow 443/tcp
sudo moatd list
```

```
[1] allow in port 22 proto tcp
[2] allow in port 443 proto tcp
```

## 4. Switch to deny-by-default

> ⚠ Make sure you've allowed the services you need *before* doing this. If
> you're connected over SSH, `allow 22/tcp` first.

```sh
sudo moatd default deny incoming
```

Existing flows survive because outbound packets populate the conntrack and
their replies match in reverse. New unsolicited inbound connections to ports
without a rule are dropped at XDP.

## 5. VPN-specific rules

If you want SSH to be reachable only over Tailscale:

```sh
sudo moatd delete 1
sudo moatd allow in on tailscale0 to any port 22 proto tcp
```

`tailscale0` doesn't need to exist when you add the rule. When the interface
appears (next time you `tailscale up`), the daemon resolves its ifindex on
the next sync.

## 6. Inspect from the kernel side

```sh
sudo bpftool net show
sudo bpftool map dump name CONNTRACK | head
```

The `CONNTRACK` map should fill up as outbound flows establish.

## 7. Reset

```sh
sudo moatd reset
```

Clears rules and restores allow/allow defaults. The state on disk is also
wiped.

## Where to next

- [Usage](usage.md) for every CLI command in detail.
- [Rule Grammar](rule-grammar.md) for the full mini-language reference.
- [Configuration](configuration.md) for files, env vars, and paths.
- [Architecture](architecture.md) for what happens under the hood.
