use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use moatd_common::control::{Action, Direction, Protocol, UserRule};
use moatd_common::{
    ACT_ALLOW, ACT_DENY, ACT_REJECT, DIR_IN, DIR_OUT, FAMILY_V4, FAMILY_V6, IFACE_ABSENT,
    IFACE_ANY, PROTO_ANY, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, SCHEMA_VERSION,
};

pub fn build_wire_rule(
    user: &UserRule,
    iface_ifindex: u32,
) -> Result<moatd_common::Rule> {
    let parsed_src = user.src.as_deref().map(parse_cidr).transpose()?;
    let parsed_dst = user.dst.as_deref().map(parse_cidr).transpose()?;

    let family = match (parsed_src, parsed_dst) {
        (Some(a), Some(b)) if a.family != b.family => {
            bail!("src and dst address families mismatch")
        }
        (Some(a), _) => a.family,
        (_, Some(b)) => b.family,
        (None, None) => FAMILY_V4,
    };

    let src = parsed_src.unwrap_or(any_cidr(family));
    let dst = parsed_dst.unwrap_or(any_cidr(family));

    let (src_port_min, src_port_max) = match &user.src_port {
        Some(p) => parse_port_range(p)?,
        None => (0, 0),
    };
    let (dst_port_min, dst_port_max) = match &user.dst_port {
        Some(p) => parse_port_range(p)?,
        None => (0, 0),
    };

    Ok(moatd_common::Rule {
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
        enabled: 1,
        _pad: [0; 3],
    })
}

pub fn empty_wire_rule() -> moatd_common::Rule {
    moatd_common::Rule::empty()
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

#[allow(dead_code)]
fn icmp_proto_for_family(family: u8) -> u8 {
    if family == FAMILY_V6 {
        PROTO_ICMPV6
    } else {
        PROTO_ICMP
    }
}

fn any_cidr(family: u8) -> moatd_common::IpCidr {
    if family == FAMILY_V6 {
        moatd_common::IpCidr::any_v6()
    } else {
        moatd_common::IpCidr::any_v4()
    }
}

pub fn resolve_iface(name: Option<&str>) -> u32 {
    let Some(name) = name else { return IFACE_ANY };
    match std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex")) {
        Ok(s) => s.trim().parse::<u32>().unwrap_or(IFACE_ABSENT),
        Err(_) => IFACE_ABSENT,
    }
}

pub fn parse_cidr(s: &str) -> Result<moatd_common::IpCidr> {
    let (addr_s, prefix_s) = match s.rsplit_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    if let Ok(addr) = Ipv4Addr::from_str(addr_s) {
        let prefix = match prefix_s {
            Some(p) => p.parse::<u8>().context("invalid CIDR prefix")?,
            None => 32,
        };
        if prefix > 32 {
            bail!("CIDR prefix `{prefix}` out of range for IPv4");
        }
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&addr.octets());
        return Ok(moatd_common::IpCidr {
            family: FAMILY_V4,
            prefix,
            _pad: [0; 2],
            addr: bytes,
        });
    }
    if let Ok(addr) = Ipv6Addr::from_str(addr_s) {
        let prefix = match prefix_s {
            Some(p) => p.parse::<u8>().context("invalid CIDR prefix")?,
            None => 128,
        };
        if prefix > 128 {
            bail!("CIDR prefix `{prefix}` out of range for IPv6");
        }
        return Ok(moatd_common::IpCidr {
            family: FAMILY_V6,
            prefix,
            _pad: [0; 2],
            addr: addr.octets(),
        });
    }
    Err(anyhow!("invalid IP address `{addr_s}`"))
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
