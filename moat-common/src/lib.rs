#![cfg_attr(not(feature = "user"), no_std)]

pub const SCHEMA_VERSION: u8 = 1;
pub const RULES_MAX: u32 = 256;
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

pub const CONNTRACK_MAX_ENTRIES: u32 = 65_536;
pub const CONNTRACK_TTL_NS: u64 = 60_000_000_000;

#[repr(C)]
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
    pub priority: u32,
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
            priority: 0,
            enabled: 0,
            _pad: [0; 3],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
pub struct GlobalConfig {
    pub logging_enabled: u8,
    pub log_level: u8,
    pub _pad: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
pub struct ConnVal {
    pub last_seen_ns: u64,
}

#[cfg(feature = "user")]
mod aya_impls {
    use super::*;
    unsafe impl aya::Pod for Rule {}
    unsafe impl aya::Pod for IpCidr {}
    unsafe impl aya::Pod for DropEvent {}
    unsafe impl aya::Pod for GlobalConfig {}
    unsafe impl aya::Pod for ConnKey {}
    unsafe impl aya::Pod for ConnVal {}
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
