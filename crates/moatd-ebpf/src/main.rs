#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_ktime_get_coarse_ns,
    macros::{classifier, map, xdp},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{TcContext, XdpContext},
};
use moatd_common::{
    ConnKey, ConnVal, DropEvent, GlobalConfig, IpCidr, LogTokens, Rule, ACT_ALLOW,
    CONNTRACK_MAX_ENTRIES, CONNTRACK_REFRESH_NS, CONNTRACK_TTL_NS, DIR_IN, DIR_OUT, FAMILY_V4,
    FAMILY_V6, IFACE_ANY, LOG_BUCKET_MAX, LOG_BUCKET_REFILL_NS, POLICY_IN, POLICY_OUT, PROTO_ANY,
    PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, RINGBUF_BYTES, RULES_MAX, RULES_SLOTS,
    RULE_ID_DEFAULT,
};
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
};

#[map]
static RULES: Array<Rule> = Array::with_max_entries(RULES_SLOTS, 0);

#[map]
static DEFAULT_POLICY: Array<u8> = Array::with_max_entries(3, 0);

#[map]
static CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

#[map]
static CONNTRACK: LruHashMap<ConnKey, ConnVal> =
    LruHashMap::with_max_entries(CONNTRACK_MAX_ENTRIES, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_BYTES, 0);

#[map]
static LOG_TOKENS: PerCpuArray<LogTokens> = PerCpuArray::with_max_entries(1, 0);

// Per-interface L2 header length. The loader populates this at attach time:
// 14 for Ethernet devices, 0 for raw-L3 devices (tun/wireguard, e.g.
// tailscale0). An interface not present in the map defaults to Ethernet.
#[map]
static IFACE_L2: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

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

// IPv6 extension-header next-header values we walk past to reach the upper
// layer. ESP/AH and anything unrecognised terminate the walk (we can't see
// ports through them anyway).
const NH_HOPOPT: u8 = 0;
const NH_ROUTING: u8 = 43;
const NH_FRAGMENT: u8 = 44;
const NH_DSTOPTS: u8 = 60;
const NH_MOBILITY: u8 = 135;
// Bounds on the ext-header walk: keep the offset range tight for the verifier
// and cap work on crafted chains.
const MAX_V6_EXT_HDRS: u32 = 4;
const MAX_V6_EXT_BYTES: usize = 64;

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
    let end = data.checked_add(offset).and_then(|x| x.checked_add(mem::size_of::<T>())).ok_or(())?;
    if end > data_end {
        return Err(());
    }
    Ok((data + offset) as *const T)
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;

#[inline(always)]
unsafe fn ethertype_at(data: usize, data_end: usize, off: usize) -> Result<u16, ()> {
    let p: *const u16 = ptr_at_data(data, data_end, off)?;
    Ok(u16::from_be(core::ptr::read_unaligned(p)))
}

#[inline(always)]
fn l2_off_for(ifindex: u32) -> usize {
    match unsafe { IFACE_L2.get(&ifindex) } {
        Some(&v) => v as usize,
        None => EthHdr::LEN,
    }
}

fn try_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let l2_off = l2_off_for(ifindex);
    let data = ctx.data();
    let data_end = ctx.data_end();

    let Some(parsed) = parse_packet(data, data_end, l2_off)? else {
        return Ok(xdp_action::XDP_PASS);
    };

    if is_ndp(&parsed) {
        return Ok(xdp_action::XDP_PASS);
    }

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
        let now = unsafe { bpf_ktime_get_coarse_ns() };
        if now.saturating_sub(v.last_seen_ns) < CONNTRACK_TTL_NS {
            // Intentionally no refresh on ingress: only the egress side keeps the
            // entry alive. Otherwise a spoofed reply could indefinitely renew it.
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let (chosen, rule_id) = walk_rules(DIR_IN, ifindex, &parsed);
    if chosen == ACT_ALLOW {
        Ok(xdp_action::XDP_PASS)
    } else {
        emit_drop(ifindex, &parsed, rule_id);
        Ok(xdp_action::XDP_DROP)
    }
}

fn try_egress(ctx: &TcContext) -> Result<i32, ()> {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let l2_off = l2_off_for(ifindex);
    let data = ctx.data();
    let data_end = ctx.data_end();

    let Some(parsed) = parse_packet(data, data_end, l2_off)? else {
        return Ok(TC_ACT_PIPE);
    };

    if is_ndp(&parsed) {
        return Ok(TC_ACT_PIPE);
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
    let now = unsafe { bpf_ktime_get_coarse_ns() };

    // Established outbound flow: skip the rule walk, refresh at most every
    // CONNTRACK_REFRESH_NS. A rule added mid-flow only applies once the entry expires.
    if let Some(v) = unsafe { CONNTRACK.get(&forward_key) } {
        let age = now.saturating_sub(v.last_seen_ns);
        if age < CONNTRACK_TTL_NS {
            if age >= CONNTRACK_REFRESH_NS {
                let _ = CONNTRACK.insert(&forward_key, &ConnVal { last_seen_ns: now }, 0);
            }
            return Ok(TC_ACT_PIPE);
        }
    }

    let (chosen, rule_id) = walk_rules(DIR_OUT, ifindex, &parsed);
    if chosen != ACT_ALLOW {
        emit_drop(ifindex, &parsed, rule_id);
        return Ok(TC_ACT_SHOT);
    }

    let _ = CONNTRACK.insert(&forward_key, &ConnVal { last_seen_ns: now }, 0);
    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn is_ndp(p: &Parsed) -> bool {
    p.family == FAMILY_V6
        && p.proto_byte == PROTO_ICMPV6
        && matches!(p.icmp_type, ICMPV6_RS | ICMPV6_RA | ICMPV6_NS | ICMPV6_NA | ICMPV6_REDIRECT)
}

#[inline(always)]
fn parse_packet(data: usize, data_end: usize, l2_off: usize) -> Result<Option<Parsed>, ()> {
    // Pass a literal IP offset (0 or EthHdr::LEN) into the parsers; threading the
    // runtime map value makes every packet read variable-offset and blows the
    // verifier's complexity limit. See project_ebpf_verifier_budget.
    if l2_off == 0 {
        // Raw L3 (tun/wireguard): family from the IP version nibble. Two bytes,
        // not one: the verifier rejects a 1-byte packet read here.
        let head: *const [u8; 2] = unsafe { ptr_at_data(data, data_end, 0)? };
        return match unsafe { core::ptr::read_unaligned(head) }[0] >> 4 {
            4 => parse_v4(data, data_end, 0),
            6 => parse_v6(data, data_end, 0),
            _ => Ok(None),
        };
    }
    // Ethernet, transparently skipping up to two 802.1Q tags (each adds 4 bytes
    // before the IP header). Literal IP offsets per tag depth keep the
    // verifier's packet offsets constant.
    match unsafe { ethertype_at(data, data_end, 12)? } {
        ETH_P_IP => parse_v4(data, data_end, EthHdr::LEN),
        ETH_P_IPV6 => parse_v6(data, data_end, EthHdr::LEN),
        ETH_P_8021Q | ETH_P_8021AD => match unsafe { ethertype_at(data, data_end, 16)? } {
            ETH_P_IP => parse_v4(data, data_end, 18),
            ETH_P_IPV6 => parse_v6(data, data_end, 18),
            ETH_P_8021Q | ETH_P_8021AD => match unsafe { ethertype_at(data, data_end, 20)? } {
                ETH_P_IP => parse_v4(data, data_end, 22),
                ETH_P_IPV6 => parse_v6(data, data_end, 22),
                _ => Ok(None),
            },
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}

#[inline(always)]
fn parse_v4(data: usize, data_end: usize, ip_off: usize) -> Result<Option<Parsed>, ()> {
    let ipv4: *const Ipv4Hdr = unsafe { ptr_at_data(data, data_end, ip_off)? };
    let src_be = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv4).src_addr)) };
    let dst_be = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv4).dst_addr)) };
    let ip_proto = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv4).proto)) } as u8;
    let frag_off_be = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv4).frag_off)) };
    let ihl = unsafe { (*ipv4).ihl() } as usize;
    if !(5..=15).contains(&ihl) {
        return Err(());
    }
    let l4_off = ip_off + ihl * 4;

    // Non-initial fragments have no L4 header; match on protocol only rather
    // than reading payload bytes as ports (a misclassification / evasion).
    let noninitial_fragment = (u16::from_be(frag_off_be) & 0x1fff) != 0;
    let (src_port, dst_port, proto_byte, icmp_type) = if noninitial_fragment {
        (0, 0, normalize_proto(ip_proto, false), 0)
    } else {
        parse_l4(data, data_end, l4_off, ip_proto, false)?
    };

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
fn parse_v6(data: usize, data_end: usize, ip_off: usize) -> Result<Option<Parsed>, ()> {
    let ipv6: *const Ipv6Hdr = unsafe { ptr_at_data(data, data_end, ip_off)? };
    let next_hdr =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ipv6).next_hdr)) } as u8;
    let src_addr: [u8; 16] = unsafe { (*ipv6).src_addr.in6_u.u6_addr8 };
    let dst_addr: [u8; 16] = unsafe { (*ipv6).dst_addr.in6_u.u6_addr8 };

    let (proto, l4_off, noninitial_fragment) =
        walk_v6_ext(data, data_end, next_hdr, ip_off + Ipv6Hdr::LEN)?;

    let (src_port, dst_port, proto_byte, icmp_type) = if noninitial_fragment {
        (0, 0, normalize_proto(proto, true), 0)
    } else {
        parse_l4(data, data_end, l4_off, proto, true)?
    };

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

#[repr(C)]
struct ExtTlv {
    next_hdr: u8,
    hdr_ext_len: u8,
}

#[repr(C)]
struct FragHdr {
    next_hdr: u8,
    _reserved: u8,
    frag_off: u16,
    _ident: u32,
}

/// Walk the IPv6 ext-header chain to the upper-layer protocol. Without it a
/// prepended ext header makes proto/port rules silently not match (a bypass).
/// Returns (proto, l4 offset, is-non-initial-fragment).
#[inline(always)]
fn walk_v6_ext(
    data: usize,
    data_end: usize,
    mut next_hdr: u8,
    start: usize,
) -> Result<(u8, usize, bool), ()> {
    let mut off = start;
    for _ in 0..MAX_V6_EXT_HDRS {
        if off > start + MAX_V6_EXT_BYTES {
            return Err(());
        }
        match next_hdr {
            NH_HOPOPT | NH_ROUTING | NH_DSTOPTS | NH_MOBILITY => {
                let eh: *const ExtTlv = unsafe { ptr_at_data(data, data_end, off)? };
                next_hdr =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eh).next_hdr)) };
                let ext_len =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eh).hdr_ext_len)) }
                        as usize;
                off = off.checked_add((ext_len + 1) * 8).ok_or(())?;
            }
            NH_FRAGMENT => {
                let fh: *const FragHdr = unsafe { ptr_at_data(data, data_end, off)? };
                let next =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*fh).next_hdr)) };
                let frag_off =
                    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*fh).frag_off)) };
                next_hdr = next;
                off = off.checked_add(8).ok_or(())?;
                // The fragment offset is the high 13 bits of the field.
                if (u16::from_be(frag_off) & 0xfff8) != 0 {
                    return Ok((next_hdr, off, true));
                }
            }
            _ => return Ok((next_hdr, off, false)),
        }
    }
    Err(())
}

#[inline(always)]
fn normalize_proto(proto: u8, is_v6: bool) -> u8 {
    match proto {
        PROTO_TCP => PROTO_TCP,
        PROTO_UDP => PROTO_UDP,
        PROTO_ICMP if !is_v6 => PROTO_ICMP,
        PROTO_ICMPV6 if is_v6 => PROTO_ICMPV6,
        _ => PROTO_ANY,
    }
}

#[inline(always)]
fn parse_l4(
    data: usize,
    data_end: usize,
    l4_off: usize,
    proto: u8,
    is_v6: bool,
) -> Result<(u16, u16, u8, u8), ()> {
    Ok(match proto {
        // Only the first 4 bytes (source+dest ports) are needed; reading them
        // alone rather than the full TCP/UDP header keeps the bounds proof small.
        PROTO_TCP => {
            let (s, d) = read_ports(data, data_end, l4_off)?;
            (s, d, PROTO_TCP, 0)
        }
        PROTO_UDP => {
            let (s, d) = read_ports(data, data_end, l4_off)?;
            (s, d, PROTO_UDP, 0)
        }
        PROTO_ICMP if !is_v6 => parse_icmp(data, data_end, l4_off, PROTO_ICMP)?,
        PROTO_ICMPV6 if is_v6 => parse_icmp(data, data_end, l4_off, PROTO_ICMPV6)?,
        _ => (0, 0, PROTO_ANY, 0),
    })
}

#[repr(C)]
struct L4Ports {
    source: u16,
    dest: u16,
}

#[inline(always)]
fn read_ports(data: usize, data_end: usize, l4_off: usize) -> Result<(u16, u16), ()> {
    let p: *const L4Ports = unsafe { ptr_at_data(data, data_end, l4_off)? };
    let source = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*p).source)) };
    let dest = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*p).dest)) };
    Ok((u16::from_be(source), u16::from_be(dest)))
}

#[repr(C)]
struct IcmpHead {
    ty: u8,
    code: u8,
    checksum: u16,
    id: u16,
    seq: u16,
}

#[inline(always)]
fn parse_icmp(
    data: usize,
    data_end: usize,
    l4_off: usize,
    proto: u8,
) -> Result<(u16, u16, u8, u8), ()> {
    // Read the type and id fields in one bounded packet access so the verifier
    // sees a single packet-range proof for both bytes. Two separate
    // `ptr_at_data` calls trip the verifier on some kernels because it loses
    // track of overlapping bounds. Echo request and echo reply share the same
    // id; other ICMP types reuse these bytes for other purposes, which is
    // harmless here because non-echo flows are unlikely to match anything in
    // CONNTRACK anyway.
    let head: *const IcmpHead = unsafe { ptr_at_data(data, data_end, l4_off)? };
    let icmp_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*head).ty)) };
    let id_be = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*head).id)) };
    let id = u16::from_be(id_be);
    // Store the id in BOTH port slots so the ConnKey reverse-swap done at
    // XDP ingress lookup is a no-op for ICMP -- request and reply share the
    // same id, so a symmetric key matches in either direction.
    Ok((id, id, proto, icmp_type))
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
    let mask: u32 = if prefix >= 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
    (cidr_word & mask) == (addr_word & mask)
}

#[inline(always)]
fn be64(b: &[u8; 16], lo: usize) -> u64 {
    u64::from_be_bytes([
        b[lo],
        b[lo + 1],
        b[lo + 2],
        b[lo + 3],
        b[lo + 4],
        b[lo + 5],
        b[lo + 6],
        b[lo + 7],
    ])
}

#[inline(always)]
fn cidr_contains_v6(cidr: &IpCidr, addr: &[u8; 16]) -> bool {
    let prefix = cidr.prefix as u32;
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    // Two 64-bit word compares, not a 16-byte loop: that loop (run src+dst per
    // rule across 256 slots) was the dominant source of verifier state.
    let (c_hi, c_lo) = (be64(&cidr.addr, 0), be64(&cidr.addr, 8));
    let (a_hi, a_lo) = (be64(addr, 0), be64(addr, 8));
    if prefix <= 64 {
        let mask = if prefix == 64 { u64::MAX } else { u64::MAX << (64 - prefix) };
        (c_hi & mask) == (a_hi & mask)
    } else {
        if c_hi != a_hi {
            return false;
        }
        let rem = prefix - 64;
        let mask = if rem >= 64 { u64::MAX } else { u64::MAX << (64 - rem) };
        (c_lo & mask) == (a_lo & mask)
    }
}

#[inline(always)]
fn walk_rules(direction: u8, ifindex: u32, p: &Parsed) -> (u8, u32) {
    let mut chosen: u8 = u8::MAX;
    let mut matched_id: u32 = RULE_ID_DEFAULT;
    // Active bank + live rule count, so we scan only real rules from the bank
    // not being rewritten. bank is 0/1; base selects its half of RULES.
    let (base, count) = match CONFIG.get(0) {
        Some(c) => ((c.active_bank as u32 & 1) * RULES_MAX, c.rule_count as u32),
        None => (0, 0),
    };
    for i in 0..RULES_MAX {
        if chosen != u8::MAX || i >= count {
            break;
        }
        let Some(rule) = RULES.get(base + i) else { break };
        if rule.direction != direction {
            continue;
        }
        if rule.iface_ifindex != IFACE_ANY && rule.iface_ifindex != ifindex {
            continue;
        }
        if rule.proto != PROTO_ANY && rule.proto != p.proto_byte {
            continue;
        }
        // Cheap integer port checks before the CIDR word compares.
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
        if !cidr_contains(&rule.src, &p.src_addr, p.family) {
            continue;
        }
        if !cidr_contains(&rule.dst, &p.dst_addr, p.family) {
            continue;
        }
        chosen = rule.action;
        matched_id = i;
    }

    if chosen == u8::MAX {
        let slot = if direction == DIR_IN { POLICY_IN } else { POLICY_OUT };
        chosen = DEFAULT_POLICY.get(slot).copied().unwrap_or(ACT_ALLOW);
        matched_id = RULE_ID_DEFAULT;
    }
    (chosen, matched_id)
}

#[inline(always)]
fn logging_enabled() -> bool {
    CONFIG.get(0).map(|c| c.logging_enabled).unwrap_or(0) != 0
}

#[inline(always)]
fn try_take_token(now: u64) -> bool {
    let Some(ptr) = LOG_TOKENS.get_ptr_mut(0) else {
        return false;
    };
    // SAFETY: per-CPU array slot; no contention on the same CPU.
    let bucket = unsafe { &mut *ptr };
    let elapsed = now.saturating_sub(bucket.last_refill_ns);
    if elapsed >= LOG_BUCKET_REFILL_NS {
        let new_tokens = (elapsed / LOG_BUCKET_REFILL_NS) as u32;
        let total = bucket.tokens.saturating_add(new_tokens);
        bucket.tokens = if total > LOG_BUCKET_MAX { LOG_BUCKET_MAX } else { total };
        bucket.last_refill_ns = now;
    }
    if bucket.tokens > 0 {
        bucket.tokens -= 1;
        true
    } else {
        false
    }
}

#[inline(always)]
fn emit_drop(ifindex: u32, p: &Parsed, rule_id: u32) {
    if !logging_enabled() {
        return;
    }
    let now = unsafe { bpf_ktime_get_coarse_ns() };
    if !try_take_token(now) {
        return;
    }
    let Some(mut entry) = EVENTS.reserve::<DropEvent>(0) else {
        return;
    };
    let event = DropEvent {
        ts_ns: now,
        ifindex,
        rule_id,
        src: p.src_addr,
        dst: p.dst_addr,
        src_port: p.src_port,
        dst_port: p.dst_port,
        proto: p.proto_byte,
        family: p.family,
        tcp_flags: 0,
        _pad: 0,
    };
    entry.write(event);
    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
