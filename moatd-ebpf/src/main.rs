#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map, xdp},
    maps::{Array, LruHashMap},
    programs::{TcContext, XdpContext},
};
use moatd_common::{
    ConnKey, ConnVal, GlobalConfig, IpCidr, Rule, ACT_ALLOW, CONNTRACK_MAX_ENTRIES,
    CONNTRACK_TTL_NS, DIR_IN, DIR_OUT, FAMILY_V4, FAMILY_V6, IFACE_ANY, POLICY_IN, POLICY_OUT,
    PROTO_ANY, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, RULES_MAX,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static RULES: Array<Rule> = Array::with_max_entries(RULES_MAX, 0);

#[map]
static DEFAULT_POLICY: Array<u8> = Array::with_max_entries(3, 0);

#[map]
static CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

#[map]
static CONNTRACK: LruHashMap<ConnKey, ConnVal> =
    LruHashMap::with_max_entries(CONNTRACK_MAX_ENTRIES, 0);

#[derive(Copy, Clone)]
struct Parsed {
    family: u8,
    proto_byte: u8,
    icmp_type: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
}

const ICMPV6_RS: u8 = 133;
const ICMPV6_RA: u8 = 134;
const ICMPV6_NS: u8 = 135;
const ICMPV6_NA: u8 = 136;
const ICMPV6_REDIRECT: u8 = 137;

#[xdp]
pub fn moat_ingress(ctx: XdpContext) -> u32 {
    match try_ingress(&ctx) {
        Ok(a) => a,
        Err(()) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn moat_egress(ctx: TcContext) -> i32 {
    match try_egress(&ctx) {
        Ok(a) => a,
        Err(()) => TC_ACT_SHOT,
    }
}

#[inline(always)]
unsafe fn ptr_at_data<T>(data: usize, data_end: usize, offset: usize) -> Result<*const T, ()> {
    let end = data
        .checked_add(offset)
        .and_then(|x| x.checked_add(mem::size_of::<T>()))
        .ok_or(())?;
    if end > data_end {
        return Err(());
    }
    Ok((data + offset) as *const T)
}

fn try_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let data = ctx.data();
    let data_end = ctx.data_end();

    let Some(parsed) = parse_packet(data, data_end)? else {
        return Ok(xdp_action::XDP_PASS);
    };

    if is_ndp(&parsed) {
        return Ok(xdp_action::XDP_PASS);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let reverse_key = ConnKey {
        proto: parsed.proto_byte,
        family: parsed.family,
        _pad: [0; 2],
        src_addr: parsed.dst_addr,
        dst_addr: parsed.src_addr,
        src_port: parsed.dst_port,
        dst_port: parsed.src_port,
    };
    if let Some(v) = unsafe { CONNTRACK.get(&reverse_key) } {
        if now.saturating_sub(v.last_seen_ns) < CONNTRACK_TTL_NS {
            // Intentionally no refresh on ingress: only the egress side keeps the
            // entry alive. Otherwise a spoofed reply could indefinitely renew it.
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let chosen = walk_rules(DIR_IN, ifindex, &parsed);
    Ok(if chosen == ACT_ALLOW {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    })
}

fn try_egress(ctx: &TcContext) -> Result<i32, ()> {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let data = ctx.data();
    let data_end = ctx.data_end();

    let Some(parsed) = parse_packet(data, data_end)? else {
        return Ok(TC_ACT_PIPE);
    };

    if is_ndp(&parsed) {
        return Ok(TC_ACT_PIPE);
    }

    let chosen = walk_rules(DIR_OUT, ifindex, &parsed);
    if chosen != ACT_ALLOW {
        return Ok(TC_ACT_SHOT);
    }

    let forward_key = ConnKey {
        proto: parsed.proto_byte,
        family: parsed.family,
        _pad: [0; 2],
        src_addr: parsed.src_addr,
        dst_addr: parsed.dst_addr,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let _ = CONNTRACK.insert(&forward_key, &ConnVal { last_seen_ns: now }, 0);
    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn is_ndp(p: &Parsed) -> bool {
    p.family == FAMILY_V6
        && p.proto_byte == PROTO_ICMPV6
        && matches!(
            p.icmp_type,
            ICMPV6_RS | ICMPV6_RA | ICMPV6_NS | ICMPV6_NA | ICMPV6_REDIRECT
        )
}

#[inline(always)]
fn parse_packet(data: usize, data_end: usize) -> Result<Option<Parsed>, ()> {
    let eth: *const EthHdr = unsafe { ptr_at_data(data, data_end, 0)? };
    let ether_type =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).ether_type)) };
    match ether_type {
        EtherType::Ipv4 => parse_v4(data, data_end),
        EtherType::Ipv6 => parse_v6(data, data_end),
        _ => Ok(None),
    }
}

#[inline(always)]
fn parse_v4(data: usize, data_end: usize) -> Result<Option<Parsed>, ()> {
    let ipv4: *const Ipv4Hdr = unsafe { ptr_at_data(data, data_end, EthHdr::LEN)? };
    let src_be = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv4).src_addr)) };
    let dst_be = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv4).dst_addr)) };
    let ip_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv4).proto)) };
    let ihl = unsafe { (*ipv4).ihl() } as usize;
    if !(5..=15).contains(&ihl) {
        return Err(());
    }
    let l4_off = EthHdr::LEN + ihl * 4;

    let (src_port, dst_port, proto_byte, icmp_type) =
        parse_l4(data, data_end, l4_off, ip_proto, false)?;

    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&src_be.to_ne_bytes());
    dst_addr[..4].copy_from_slice(&dst_be.to_ne_bytes());

    Ok(Some(Parsed {
        family: FAMILY_V4,
        proto_byte,
        icmp_type,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    }))
}

#[inline(always)]
fn parse_v6(data: usize, data_end: usize) -> Result<Option<Parsed>, ()> {
    let ipv6: *const Ipv6Hdr = unsafe { ptr_at_data(data, data_end, EthHdr::LEN)? };
    let next_hdr = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv6).next_hdr)) };
    let src_addr: [u8; 16] = unsafe { (*ipv6).src_addr.in6_u.u6_addr8 };
    let dst_addr: [u8; 16] = unsafe { (*ipv6).dst_addr.in6_u.u6_addr8 };
    let l4_off = EthHdr::LEN + Ipv6Hdr::LEN;

    let (src_port, dst_port, proto_byte, icmp_type) =
        parse_l4(data, data_end, l4_off, next_hdr, true)?;

    Ok(Some(Parsed {
        family: FAMILY_V6,
        proto_byte,
        icmp_type,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    }))
}

#[inline(always)]
fn parse_l4(
    data: usize,
    data_end: usize,
    l4_off: usize,
    proto: IpProto,
    is_v6: bool,
) -> Result<(u16, u16, u8, u8), ()> {
    Ok(match proto {
        IpProto::Tcp => {
            let tcp: *const TcpHdr = unsafe { ptr_at_data(data, data_end, l4_off)? };
            let source = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).source)) };
            let dest = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).dest)) };
            (u16::from_be(source), u16::from_be(dest), PROTO_TCP, 0)
        }
        IpProto::Udp => {
            let udp: *const UdpHdr = unsafe { ptr_at_data(data, data_end, l4_off)? };
            let source = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp).source)) };
            let dest = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp).dest)) };
            (u16::from_be(source), u16::from_be(dest), PROTO_UDP, 0)
        }
        IpProto::Icmp if !is_v6 => (0, 0, PROTO_ICMP, 0),
        IpProto::Ipv6Icmp if is_v6 => {
            let ty_ptr: *const u8 = unsafe { ptr_at_data(data, data_end, l4_off)? };
            (0, 0, PROTO_ICMPV6, unsafe { core::ptr::read_unaligned(ty_ptr) })
        }
        _ => (0, 0, PROTO_ANY, 0),
    })
}

#[inline(always)]
fn cidr_contains(cidr: &IpCidr, addr: &[u8; 16], family: u8) -> bool {
    // A wildcard CIDR (prefix 0) matches any family, mirroring ufw semantics where
    // a rule without src/dst should match both v4 and v6. Explicit non-wildcard
    // CIDRs still enforce a family match.
    if cidr.prefix == 0 {
        return true;
    }
    if cidr.family != family {
        return false;
    }
    if family == FAMILY_V4 {
        cidr_contains_v4(cidr, addr)
    } else {
        cidr_contains_v6(cidr, addr)
    }
}

#[inline(always)]
fn cidr_contains_v4(cidr: &IpCidr, addr: &[u8; 16]) -> bool {
    let prefix = cidr.prefix as u32;
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let cidr_word = u32::from_be_bytes([cidr.addr[0], cidr.addr[1], cidr.addr[2], cidr.addr[3]]);
    let addr_word = u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]);
    let mask: u32 = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (cidr_word & mask) == (addr_word & mask)
}

#[inline(always)]
fn cidr_contains_v6(cidr: &IpCidr, addr: &[u8; 16]) -> bool {
    let mut prefix = cidr.prefix as usize;
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let mut i = 0;
    while i < 16 {
        if prefix == 0 {
            return true;
        }
        if prefix >= 8 {
            if cidr.addr[i] != addr[i] {
                return false;
            }
            prefix -= 8;
        } else {
            let mask = !((1u8 << (8 - prefix)) - 1);
            return (cidr.addr[i] & mask) == (addr[i] & mask);
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn walk_rules(direction: u8, ifindex: u32, p: &Parsed) -> u8 {
    let mut chosen: u8 = u8::MAX;
    for i in 0..RULES_MAX {
        if chosen != u8::MAX {
            break;
        }
        let Some(rule) = RULES.get(i) else { break };
        if rule.enabled == 0 {
            continue;
        }
        if rule.direction != direction {
            continue;
        }
        if rule.iface_ifindex != IFACE_ANY && rule.iface_ifindex != ifindex {
            continue;
        }
        if rule.proto != PROTO_ANY && rule.proto != p.proto_byte {
            continue;
        }
        if !cidr_contains(&rule.src, &p.src_addr, p.family) {
            continue;
        }
        if !cidr_contains(&rule.dst, &p.dst_addr, p.family) {
            continue;
        }
        if rule.dst_port_max != 0
            && (p.dst_port < rule.dst_port_min || p.dst_port > rule.dst_port_max)
        {
            continue;
        }
        if rule.src_port_max != 0
            && (p.src_port < rule.src_port_min || p.src_port > rule.src_port_max)
        {
            continue;
        }
        chosen = rule.action;
    }

    if chosen == u8::MAX {
        let slot = if direction == DIR_IN { POLICY_IN } else { POLICY_OUT };
        chosen = DEFAULT_POLICY.get(slot).copied().unwrap_or(ACT_ALLOW);
    }
    chosen
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
