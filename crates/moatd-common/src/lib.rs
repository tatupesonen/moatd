#![cfg_attr(not(feature = "user"), no_std)]

pub const SCHEMA_VERSION: u8 = 1;
pub const RULES_MAX: u32 = 256;
// Rules are double-buffered: the RULES array holds two banks of RULES_MAX
// slots. The loader writes the inactive bank, then flips CONFIG.active_bank, so
// the data path never reads a half-written rule.
pub const RULE_BANKS: u32 = 2;
pub const RULES_SLOTS: u32 = RULES_MAX * RULE_BANKS;
pub const RINGBUF_BYTES: u32 = 256 * 1024;

pub const POLICY_IN: u32 = 0;
pub const POLICY_OUT: u32 = 1;
pub const POLICY_FORWARD: u32 = 2;

pub const PROTO_ANY: u8 = 0;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

pub const DIR_IN: u8 = 0;
pub const DIR_OUT: u8 = 1;

pub const ACT_ALLOW: u8 = 0;
pub const ACT_DENY: u8 = 1;
pub const ACT_REJECT: u8 = 2;

pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;

pub const IFACE_ANY: u32 = 0;
pub const IFACE_ABSENT: u32 = u32::MAX;

/// A syntactically valid Linux interface name (IFNAMSIZ is 16 incl. NUL).
pub fn valid_iface_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15 && !name.bytes().any(|b| b == b'/' || b == b' ' || b == 0)
}

// Sized well above the expected live-flow count so the hash stays at a low load
// factor: a lookup miss then usually hits an empty bucket and bails, instead of
// probing an occupied one and paying a key-compare cache miss.
pub const CONNTRACK_MAX_ENTRIES: u32 = 262_144;
// 2h, so idle TCP sessions (SSH, DB) survive well past typical keepalive gaps.
// LRU eviction handles pressure; the egress-only refresh still bounds spoofing.
pub const CONNTRACK_TTL_NS: u64 = 7_200_000_000_000;
// An established egress flow refreshes its conntrack entry at most this often,
// rather than on every packet, to keep the hot path off the map write path.
pub const CONNTRACK_REFRESH_NS: u64 = 10_000_000_000;

pub const LOG_BUCKET_MAX: u32 = 100;
pub const LOG_BUCKET_REFILL_NS: u64 = 10_000_000; // ~100 tokens/s/CPU
pub const RULE_ID_DEFAULT: u32 = u32::MAX;

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct IpCidr {
    pub family: u8,
    pub prefix: u8,
    pub _pad: [u8; 2],
    pub addr: [u8; 16],
}

impl IpCidr {
    pub const fn any_v4() -> Self {
        Self { family: FAMILY_V4, prefix: 0, _pad: [0; 2], addr: [0; 16] }
    }

    pub const fn any_v6() -> Self {
        Self { family: FAMILY_V6, prefix: 0, _pad: [0; 2], addr: [0; 16] }
    }
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct Rule {
    pub version: u8,
    pub direction: u8,
    pub action: u8,
    pub proto: u8,
    pub iface_ifindex: u32,
    pub src: IpCidr,
    pub dst: IpCidr,
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub enabled: u8,
    pub _pad: [u8; 3],
}

impl Rule {
    pub const fn empty() -> Self {
        Self {
            version: SCHEMA_VERSION,
            direction: DIR_IN,
            action: ACT_ALLOW,
            proto: PROTO_ANY,
            iface_ifindex: IFACE_ANY,
            src: IpCidr::any_v4(),
            dst: IpCidr::any_v4(),
            src_port_min: 0,
            src_port_max: 0,
            dst_port_min: 0,
            dst_port_max: 0,
            enabled: 0,
            _pad: [0; 3],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct DropEvent {
    pub ts_ns: u64,
    pub ifindex: u32,
    pub rule_id: u32,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub family: u8,
    pub tcp_flags: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct GlobalConfig {
    pub logging_enabled: u8,
    pub log_level: u8,
    pub active_bank: u8,
    // Conntrack is only needed when inbound is restrictive; when 0 the data path
    // skips the per-packet conntrack lookup/insert entirely.
    pub conntrack_enabled: u8,
    pub rule_count: u16,
    pub _pad2: u16,
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ConnKey {
    pub proto: u8,
    pub family: u8,
    pub _pad: [u8; 2],
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ConnVal {
    pub last_seen_ns: u64,
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LogTokens {
    pub tokens: u32,
    pub _pad: [u8; 4],
    pub last_refill_ns: u64,
}

#[cfg(feature = "user")]
mod aya_impls {
    use super::{ConnKey, ConnVal, DropEvent, GlobalConfig, IpCidr, LogTokens, Rule};
    unsafe impl aya::Pod for Rule {}
    unsafe impl aya::Pod for IpCidr {}
    unsafe impl aya::Pod for DropEvent {}
    unsafe impl aya::Pod for GlobalConfig {}
    unsafe impl aya::Pod for ConnKey {}
    unsafe impl aya::Pod for ConnVal {}
    unsafe impl aya::Pod for LogTokens {}
}

#[cfg(feature = "user")]
pub mod control {
    use serde::{Deserialize, Serialize};

    pub const SOCKET_PATH: &str = "/run/moatd/control.sock";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
    #[serde(rename_all = "lowercase")]
    pub enum Direction {
        #[default]
        In,
        Out,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
    #[serde(rename_all = "lowercase")]
    pub enum Action {
        #[default]
        Allow,
        Deny,
        Reject,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
    #[serde(rename_all = "lowercase")]
    pub enum Protocol {
        Tcp,
        Udp,
        Icmp,
        #[default]
        Any,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UserRule {
        pub direction: Direction,
        pub action: Action,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iface: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub proto: Option<Protocol>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub src: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dst: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub src_port: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dst_port: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum Request {
        Ping,
        Status,
        ListRules,
        AddRule(UserRule),
        DeleteRule(u32),
        SetDefault { direction: Direction, action: Action },
        SetLogging { enabled: bool },
        Reset,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum Response {
        Pong,
        Ok,
        Status(StatusReport),
        Rules(Vec<UserRule>),
        Err(String),
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct StatusReport {
        pub active: bool,
        pub attached_interfaces: Vec<String>,
        pub rules: u32,
        pub schema_version: u8,
        pub default_in: Action,
        pub default_out: Action,
        pub logging_enabled: bool,
    }
}
