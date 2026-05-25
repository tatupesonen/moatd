use moat_common::control::{Action, Direction, Protocol, UserRule};
use moat_common::{FAMILY_V4, IFACE_ANY, PROTO_TCP};

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
    let wire = moat::wire::build_wire_rule(&r, 0, IFACE_ANY).unwrap();
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
    let wire = moat::wire::build_wire_rule(&r, 0, IFACE_ANY).unwrap();
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
    let wire = moat::wire::build_wire_rule(&r, 0, IFACE_ANY).unwrap();
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
    assert!(moat::wire::build_wire_rule(&r, 0, IFACE_ANY).is_err());
}
