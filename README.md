<p align="center">
  <img src="moatd.png" alt="moatd" width="100%">
</p>

<p align="center">
  A small, fast host firewall for Linux. eBPF in the kernel, ufw-style commands.
</p>

<p align="center">
  <a href="https://github.com/tatupesonen/moatd/actions"><img alt="CI" src="https://github.com/tatupesonen/moatd/actions/workflows/ci.yml/badge.svg"></a>
</p>

## What it is

A host firewall that filters packets with eBPF (XDP on ingress, TC on egress) before they reach the kernel network stack.

## Install

```sh
git clone git@github.com:tatupesonen/moatd.git
cd moatd
cargo build --release
sudo make install
sudo systemctl daemon-reload
sudo moatd enable
```

## Usage

```sh
# Allow SSH from anywhere
sudo moatd allow 22/tcp

# Allow HTTP and HTTPS
sudo moatd allow 80/tcp
sudo moatd allow 443/tcp

# Allow SSH only on the tailscale interface
sudo moatd allow in on tailscale0 to any port 22

# Block inbound HTTP
sudo moatd deny in port 80 proto tcp

# Default deny incoming (outbound replies still pass)
sudo moatd default deny incoming

# List, delete, reset
sudo moatd list
sudo moatd delete 2
sudo moatd reset

# Show status, toggle logging
sudo moatd status
sudo moatd logging on
```

Full rule grammar:

```
moatd <allow|deny|reject> [in|out]
                           [on <iface>]
                           [from <cidr>] [port <p|p-p>]
                           [to <cidr>]   [port <p|p-p>]
                           [proto tcp|udp|icmp]
```

## Documentation

The full guide lives under [`book/`](book/):

```sh
cargo install mdbook
mdbook serve book
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
