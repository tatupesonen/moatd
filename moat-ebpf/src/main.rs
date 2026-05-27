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
use moat_common::{
    ConnKey, ConnVal, GlobalConfig, IpCidr, Rule, ACT_ALLOW, CONNTRACK_MAX_ENTRIES,
    CONNTRACK_TTL_NS, DIR_IN, DIR_OUT, FAMILY_V4, IFACE_ANY, POLICY_IN, POLICY_OUT,
    PROTO_ANY, PROTO_ICMP, PROTO_TCP, PROTO_UDP, RULES_MAX,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
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
    src_addr_be: u32,
    dst_addr_be: u32,
    src_port: u16,
    dst_port: u16,
    proto_byte: u8,
}

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
    if data + offset + mem::size_of::<T>() > data_end {
        return Err(());
    }
    Ok((data + offset) as *const T)
}

fn try_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let data = ctx.data();
    let data_end = ctx.data_end();

    let Some(parsed) = parse_v4(data, data_end)? else {
        return Ok(xdp_action::XDP_PASS);
    };

    // Conntrack: reverse lookup against the egress-stored forward key.
    let now = unsafe { bpf_ktime_get_ns() };
    let reverse_key = ConnKey {
        proto: parsed.proto_byte,
        _pad: [0; 3],
        src_addr_be: parsed.dst_addr_be,
        dst_addr_be: parsed.src_addr_be,
        src_port: parsed.dst_port,
        dst_port: parsed.src_port,
    };
    if let Some(v) = unsafe { CONNTRACK.get(&reverse_key) } {
        let last = v.last_seen_ns;
        if now.saturating_sub(last) < CONNTRACK_TTL_NS {
            let _ = CONNTRACK.insert(&reverse_key, &ConnVal { last_seen_ns: now }, 0);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let chosen = walk_rules(DIR_IN, ifindex, &parsed);
    let action = if chosen == ACT_ALLOW {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    };
    Ok(action)
}

fn try_egress(ctx: &TcContext) -> Result<i32, ()> {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let data = ctx.data();
    let data_end = ctx.data_end();

    let Some(parsed) = parse_v4(data, data_end)? else {
        return Ok(TC_ACT_PIPE);
    };

    let chosen = walk_rules(DIR_OUT, ifindex, &parsed);
    if chosen != ACT_ALLOW {
        return Ok(TC_ACT_SHOT);
    }

    let forward_key = ConnKey {
        proto: parsed.proto_byte,
        _pad: [0; 3],
        src_addr_be: parsed.src_addr_be,
        dst_addr_be: parsed.dst_addr_be,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let _ = CONNTRACK.insert(&forward_key, &ConnVal { last_seen_ns: now }, 0);
    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn parse_v4(data: usize, data_end: usize) -> Result<Option<Parsed>, ()> {
    let eth: *const EthHdr = unsafe { ptr_at_data(data, data_end, 0)? };
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(None);
    }

    let ipv4: *const Ipv4Hdr = unsafe { ptr_at_data(data, data_end, EthHdr::LEN)? };
    let src_addr_be = unsafe { (*ipv4).src_addr };
    let dst_addr_be = unsafe { (*ipv4).dst_addr };
    let ip_proto = unsafe { (*ipv4).proto };
    let ihl = unsafe { (*ipv4).ihl() } as usize;
    if ihl < 5 {
        return Err(());
    }
    let l4_off = EthHdr::LEN + ihl * 4;

    let (src_port, dst_port, proto_byte) = match ip_proto {
        IpProto::Tcp => {
            let tcp: *const TcpHdr = unsafe { ptr_at_data(data, data_end, l4_off)? };
            (
                u16::from_be(unsafe { (*tcp).source }),
                u16::from_be(unsafe { (*tcp).dest }),
                PROTO_TCP,
            )
        }
        IpProto::Udp => {
            let udp: *const UdpHdr = unsafe { ptr_at_data(data, data_end, l4_off)? };
            (
                u16::from_be(unsafe { (*udp).source }),
                u16::from_be(unsafe { (*udp).dest }),
                PROTO_UDP,
            )
        }
        IpProto::Icmp => (0u16, 0u16, PROTO_ICMP),
        _ => (0u16, 0u16, PROTO_ANY),
    };

    Ok(Some(Parsed {
        src_addr_be,
        dst_addr_be,
        src_port,
        dst_port,
        proto_byte,
    }))
}

#[inline(always)]
fn cidr_contains_v4(cidr: &IpCidr, addr_be: u32) -> bool {
    if cidr.family != FAMILY_V4 {
        return false;
    }
    let prefix = cidr.prefix as u32;
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let cidr_addr = u32::from_be_bytes([
        cidr.addr[0],
        cidr.addr[1],
        cidr.addr[2],
        cidr.addr[3],
    ]);
    let addr = u32::from_be(addr_be);
    let mask: u32 = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (cidr_addr & mask) == (addr & mask)
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
        if !cidr_contains_v4(&rule.src, p.src_addr_be) {
            continue;
        }
        if !cidr_contains_v4(&rule.dst, p.dst_addr_be) {
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
