use moatd_common::control::{Action, Direction, Protocol, UserRule};
use moatd_common::{FAMILY_V4, FAMILY_V6, IFACE_ANY, PROTO_TCP};

#[test]
fn cidr_v4_with_prefix() {
    let r = UserRule {
        direction: Direction::In,
        action: Action::Allow,
        iface: None,
        proto: Some(Protocol::Tcp),
        src: Some("10.0.0.0/8".into()),
        dst: None,
        src_port: None,
        dst_port: Some("22".into()),
    };
    let wire = moatd::wire::build_wire_rule(&r, IFACE_ANY).unwrap();
    assert_eq!(wire.src.family, FAMILY_V4);
    assert_eq!(wire.src.prefix, 8);
    assert_eq!(&wire.src.addr[..4], &[10, 0, 0, 0]);
    assert_eq!(wire.dst_port_min, 22);
    assert_eq!(wire.dst_port_max, 22);
    assert_eq!(wire.proto, PROTO_TCP);
}

#[test]
fn cidr_v4_host_default_prefix() {
    let r = UserRule {
        direction: Direction::In,
        action: Action::Deny,
        iface: None,
        proto: None,
        src: Some("1.2.3.4".into()),
        dst: None,
        src_port: None,
        dst_port: None,
    };
    let wire = moatd::wire::build_wire_rule(&r, IFACE_ANY).unwrap();
    assert_eq!(wire.src.prefix, 32);
    assert_eq!(&wire.src.addr[..4], &[1, 2, 3, 4]);
}

#[test]
fn port_range() {
    let r = UserRule {
        direction: Direction::In,
        action: Action::Allow,
        iface: None,
        proto: None,
        src: None,
        dst: None,
        src_port: None,
        dst_port: Some("1000-2000".into()),
    };
    let wire = moatd::wire::build_wire_rule(&r, IFACE_ANY).unwrap();
    assert_eq!(wire.dst_port_min, 1000);
    assert_eq!(wire.dst_port_max, 2000);
}

#[test]
fn invalid_cidr_rejected() {
    let r = UserRule {
        direction: Direction::In,
        action: Action::Allow,
        iface: None,
        proto: None,
        src: Some("not-an-ip".into()),
        dst: None,
        src_port: None,
        dst_port: None,
    };
    assert!(moatd::wire::build_wire_rule(&r, IFACE_ANY).is_err());
}

#[test]
fn cidr_v6_with_prefix() {
    let r = UserRule {
        direction: Direction::In,
        action: Action::Allow,
        iface: None,
        proto: Some(Protocol::Tcp),
        src: Some("fe80::/10".into()),
        dst: None,
        src_port: None,
        dst_port: Some("22".into()),
    };
    let wire = moatd::wire::build_wire_rule(&r, IFACE_ANY).unwrap();
    assert_eq!(wire.src.family, FAMILY_V6);
    assert_eq!(wire.src.prefix, 10);
    assert_eq!(wire.src.addr[0], 0xfe);
    assert_eq!(wire.src.addr[1], 0x80);
    assert_eq!(wire.dst.family, FAMILY_V6);
    assert_eq!(wire.dst.prefix, 0);
}

#[test]
fn cidr_v6_host_default_prefix() {
    let r = UserRule {
        direction: Direction::In,
        action: Action::Deny,
        iface: None,
        proto: None,
        src: Some("2001:db8::1".into()),
        dst: None,
        src_port: None,
        dst_port: None,
    };
    let wire = moatd::wire::build_wire_rule(&r, IFACE_ANY).unwrap();
    assert_eq!(wire.src.family, FAMILY_V6);
    assert_eq!(wire.src.prefix, 128);
    assert_eq!(wire.src.addr[0], 0x20);
    assert_eq!(wire.src.addr[1], 0x01);
    assert_eq!(wire.src.addr[15], 0x01);
}

#[test]
fn mixed_v4_v6_rejected() {
    let r = UserRule {
        direction: Direction::In,
        action: Action::Allow,
        iface: None,
        proto: None,
        src: Some("10.0.0.0/8".into()),
        dst: Some("::/0".into()),
        src_port: None,
        dst_port: None,
    };
    assert!(moatd::wire::build_wire_rule(&r, IFACE_ANY).is_err());
}
