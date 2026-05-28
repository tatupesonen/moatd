# Docker Behavior

A common gripe with `ufw` is that it **doesn't filter Docker traffic**: a
`docker run -p 80:80 nginx` exposes port 80 to the world even with
`ufw default deny incoming`. moatd does the right thing here, automatically.

## Why ufw misses Docker traffic

`ufw` writes its rules into iptables `filter` chains:
`INPUT` / `OUTPUT` / `FORWARD`. Docker inserts its own DNAT rules into
`nat/PREROUTING` at `-I` (insert-at-top) priority. By the time a packet
reaches `INPUT`, Docker has already DNATed it to the container's address;
the packet is now destined for the container's bridge IP, not the host, and
takes the `FORWARD` path. Docker also inserts allow rules into `DOCKER-USER`
in front of any `ufw` rule, so even `FORWARD` decisions are bypassed.

## Why moatd doesn't have this problem

XDP runs at the driver layer, **before any iptables chain**. The kernel
hook order on ingress is:

```
NIC driver ──▶ XDP ──▶ netif_receive_skb ──▶ PREROUTING(DNAT) ──▶ routing ──▶ ...
                  ▲                            ▲
                  │                            │
                  moatd sees this              Docker rewrites here
```

So for an external connection to `host_ip:8080` that Docker would DNAT to
`container_ip:80`, the XDP program sees the original `dst_port = 8080` (and
`dst_addr = host_ip`). Its rule matching is unaffected by Docker.

```sh
# Default deny + no rule for port 8080
sudo moat default deny incoming
sudo docker run -d -p 8080:80 nginx
curl http://host_ip:8080   # ← blocked by moatd, never reaches nginx
```

## Reply traffic

The container's reply traverses:

```
nginx ──▶ veth ──▶ docker0 ──▶ POSTROUTING(SNAT) ──▶ TC egress ──▶ NIC driver
                                                       ▲
                                                       moatd sees post-SNAT
```

So moatd's TC egress sees `src = host_ip` (post-SNAT) and inserts a conntrack
entry against the remote client's address. The next inbound reply finds the
reverse-tuple match in CONNTRACK and is allowed.

## Container-internal traffic

By default moatd **skips** `docker0`, `br-*`, and `veth*` interfaces when
attaching. That means:

- Container ↔ container traffic on a Docker bridge is **not** filtered.
- Container ↔ host services via the bridge (e.g. container connects to
  `host.docker.internal`) is **not** filtered.

This is intentional: containers expect to be able to talk to each other and
to the host on their bridge networks. Filtering that would break most
docker-compose stacks.

If you do want east-west container filtering, override the skip list with
`MOAT_INTERFACES=...,docker0` or similar. That's a deliberate opt-in.

## Summary

| Concern | ufw | moatd |
| --- | --- | --- |
| `docker run -p 80:80` exposed despite `default deny` | yes (bypassed) | **no, blocked** |
| Reply traffic to allowed inbound flows | manual rules required | automatic via conntrack |
| Container ↔ container | filtered (sometimes too much) | skipped by default |
| Container ↔ host services on bridge | filtered (sometimes too much) | skipped by default |
