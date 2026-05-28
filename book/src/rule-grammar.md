# Rule Grammar

`moatd` accepts rule specs in two forms: a shorthand and a full grammar.

## Shorthand

```
moatd allow 22                  # implicit port 22, any proto
moatd allow 53/udp              # port 53 over UDP
moatd deny 25                   # block port 25
```

Used when the only thing you want to express is a destination port (and
optionally protocol).

## Full grammar

```
moat <action> [<dir>] [on <iface>] [from <cidr>] [port <p|p-p>]
                                   [to <cidr>]   [port <p|p-p>]
                                   [proto <tcp|udp|icmp>]
```

Where:

- `<action>` is `allow`, `deny`, or `reject` (currently treated as `deny`).
- `<dir>` is `in` (default) or `out`.
- `on <iface>` restricts the rule to one network interface.
- `from <cidr>` matches the packet's source address. `any` is also valid and
  is equivalent to omitting `from`.
- `to <cidr>` matches the destination address.
- `port <p|p-p>` matches the destination port (or range like `1000-2000`).
  If the `port` token follows `from`, it matches the *source* port instead.
- `proto <name>` restricts the rule to that protocol.

## Examples

```sh
# SSH only from the Tailscale subnet, only when arriving on tailscale0
moatd allow in on tailscale0 from 100.64.0.0/10 to any port 22 proto tcp

# Outbound DNS only to 1.1.1.1 and 8.8.8.8
moatd default deny outgoing
moatd allow out to 1.1.1.1 port 53 proto udp
moatd allow out to 8.8.8.8 port 53 proto udp

# Block a known-bad source
moatd deny in from 198.51.100.7 to any

# Open ephemeral port range for QUIC
moatd allow in port 50000-60000 proto udp
```

## How rules are evaluated

1. The packet is parsed (Ethernet → IPv4/IPv6 → TCP/UDP/ICMP).
2. The eBPF program does a conntrack reverse lookup. If the packet is a reply
   to a tracked outbound flow, it passes immediately. See
   [Conntrack](conntrack.md).
3. The rule list is walked top to bottom. **First match wins.** The first rule
   you added is rule #1.
4. If no rule matches, the default policy for that direction applies.

## Wildcards

A rule with no `from` or `to` matches any source and destination, **and**
any address family. This is unlike strict-family firewalls — `moatd allow 80/tcp`
allows both v4 and v6 inbound traffic to port 80, matching ufw's behavior.

If you supply an explicit CIDR (`from 10.0.0.0/8`), the rule is locked to
that family.
