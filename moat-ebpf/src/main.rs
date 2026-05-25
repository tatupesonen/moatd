#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
use moat_common::{
    GlobalConfig, IpCidr, Rule, ACT_ALLOW, DIR_IN, FAMILY_V4, IFACE_ANY,
    POLICY_IN, PROTO_ANY, PROTO_ICMP, PROTO_TCP, PROTO_UDP, RULES_MAX,
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

#[xdp]
pub fn moat_ingress(ctx: XdpContext) -> u32 {
    match try_ingress(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
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

fn try_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };

    let eth: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    match unsafe { (*eth).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
    let src_addr_be: u32 = unsafe { (*ipv4).src_addr };
    let dst_addr_be: u32 = unsafe { (*ipv4).dst_addr };
    let ip_proto: IpProto = unsafe { (*ipv4).proto };
    let ihl = unsafe { (*ipv4).ihl() } as usize;
    if ihl < 5 {
        return Err(());
    }
    let l4_off = EthHdr::LEN + ihl * 4;

    let (src_port, dst_port, proto_byte) = match ip_proto {
        IpProto::Tcp => {
            let tcp: *const TcpHdr = unsafe { ptr_at(ctx, l4_off)? };
            (
                u16::from_be(unsafe { (*tcp).source }),
                u16::from_be(unsafe { (*tcp).dest }),
                PROTO_TCP,
            )
        }
        IpProto::Udp => {
            let udp: *const UdpHdr = unsafe { ptr_at(ctx, l4_off)? };
            (
                u16::from_be(unsafe { (*udp).source }),
                u16::from_be(unsafe { (*udp).dest }),
                PROTO_UDP,
            )
        }
        IpProto::Icmp => (0u16, 0u16, PROTO_ICMP),
        _ => (0u16, 0u16, PROTO_ANY),
    };

    let mut chosen: u8 = u8::MAX;

    for i in 0..RULES_MAX {
        if chosen != u8::MAX {
            break;
        }
        let Some(rule) = RULES.get(i) else { break };
        if rule.enabled == 0 {
            continue;
        }
        if rule.direction != DIR_IN {
            continue;
        }
        if rule.iface_ifindex != IFACE_ANY && rule.iface_ifindex != ifindex {
            continue;
        }
        if rule.proto != PROTO_ANY && rule.proto != proto_byte {
            continue;
        }
        if !cidr_contains_v4(&rule.src, src_addr_be) {
            continue;
        }
        if !cidr_contains_v4(&rule.dst, dst_addr_be) {
            continue;
        }
        if rule.dst_port_max != 0
            && (dst_port < rule.dst_port_min || dst_port > rule.dst_port_max)
        {
            continue;
        }
        if rule.src_port_max != 0
            && (src_port < rule.src_port_min || src_port > rule.src_port_max)
        {
            continue;
        }
        chosen = rule.action;
    }

    if chosen == u8::MAX {
        chosen = DEFAULT_POLICY.get(POLICY_IN).copied().unwrap_or(ACT_ALLOW);
    }

    let action = if chosen == ACT_ALLOW {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    };
    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
