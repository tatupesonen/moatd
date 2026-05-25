use std::net::Ipv4Addr;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use moat_common::control::{Action, Direction, Protocol, UserRule};
use moat_common::{
    ACT_ALLOW, ACT_DENY, ACT_REJECT, DIR_IN, DIR_OUT, FAMILY_V4, IFACE_ABSENT, IFACE_ANY,
    PROTO_ANY, PROTO_ICMP, PROTO_TCP, PROTO_UDP, SCHEMA_VERSION,
};

pub fn build_wire_rule(
    user: &UserRule,
    priority: u32,
    iface_ifindex: u32,
) -> Result<moat_common::Rule> {
    let src = match &user.src {
        Some(s) => parse_cidr_v4(s)?,
        None => moat_common::IpCidr::any_v4(),
    };
    let dst = match &user.dst {
        Some(s) => parse_cidr_v4(s)?,
        None => moat_common::IpCidr::any_v4(),
    };

    let (src_port_min, src_port_max) = match &user.src_port {
        Some(p) => parse_port_range(p)?,
        None => (0, 0),
    };
    let (dst_port_min, dst_port_max) = match &user.dst_port {
        Some(p) => parse_port_range(p)?,
        None => (0, 0),
    };

    Ok(moat_common::Rule {
        version: SCHEMA_VERSION,
        direction: direction_byte(user.direction),
        action: action_byte(user.action),
        proto: proto_byte(user.proto),
        iface_ifindex,
        src,
        dst,
        src_port_min,
        src_port_max,
        dst_port_min,
        dst_port_max,
        priority,
        enabled: 1,
        _pad: [0; 3],
    })
}

pub fn empty_wire_rule() -> moat_common::Rule {
    moat_common::Rule::empty()
}

pub fn direction_byte(d: Direction) -> u8 {
    match d {
        Direction::In => DIR_IN,
        Direction::Out => DIR_OUT,
    }
}

pub fn action_byte(a: Action) -> u8 {
    match a {
        Action::Allow => ACT_ALLOW,
        Action::Deny => ACT_DENY,
        Action::Reject => ACT_REJECT,
    }
}

pub fn proto_byte(p: Option<Protocol>) -> u8 {
    match p {
        None | Some(Protocol::Any) => PROTO_ANY,
        Some(Protocol::Tcp) => PROTO_TCP,
        Some(Protocol::Udp) => PROTO_UDP,
        Some(Protocol::Icmp) => PROTO_ICMP,
    }
}

pub fn resolve_iface(name: Option<&str>) -> u32 {
    let Some(name) = name else { return IFACE_ANY };
    match std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex")) {
        Ok(s) => s.trim().parse::<u32>().unwrap_or(IFACE_ABSENT),
        Err(_) => IFACE_ABSENT,
    }
}

fn parse_cidr_v4(s: &str) -> Result<moat_common::IpCidr> {
    let (addr_s, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().context("invalid CIDR prefix")?),
        None => (s, 32),
    };
    let addr = Ipv4Addr::from_str(addr_s).map_err(|_| anyhow!("invalid IPv4 address `{addr_s}`"))?;
    if prefix > 32 {
        bail!("CIDR prefix `{prefix}` out of range for IPv4");
    }
    let octets = addr.octets();
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&octets);
    Ok(moat_common::IpCidr {
        family: FAMILY_V4,
        prefix,
        _pad: [0; 2],
        addr: bytes,
    })
}

fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    if let Some((lo, hi)) = s.split_once('-') {
        let lo: u16 = lo.parse().context("invalid port range start")?;
        let hi: u16 = hi.parse().context("invalid port range end")?;
        if lo == 0 || hi == 0 || lo > hi {
            bail!("invalid port range `{s}`");
        }
        Ok((lo, hi))
    } else {
        let p: u16 = s.parse().context("invalid port")?;
        if p == 0 {
            bail!("port 0 not allowed");
        }
        Ok((p, p))
    }
}
