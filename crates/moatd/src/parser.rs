use anyhow::{bail, Context, Result};
use moatd_common::control::{Action, Direction, Protocol, UserRule};

use crate::apps::{self, AppProfile};

/// Parse a rule spec into one or more `UserRule`s. Most specs produce a
/// single rule; app profiles with multi-port lists (e.g. `web` →
/// `[80, 443]`) expand to one rule per port.
pub fn parse_rule_spec(action: Action, tokens: &[String]) -> Result<Vec<UserRule>> {
    if tokens.is_empty() {
        bail!("empty rule spec");
    }

    if tokens.len() == 1 {
        if let Some(rules) = parse_shorthand(&tokens[0], action)? {
            return Ok(rules);
        }
    }

    Ok(vec![parse_full_grammar(action, tokens)?])
}

fn parse_shorthand(tok: &str, action: Action) -> Result<Option<Vec<UserRule>>> {
    if tok.parse::<u16>().is_ok() {
        return Ok(Some(vec![rule_with_port(action, tok.to_string(), None)]));
    }
    if let Some((port, proto)) = tok.split_once('/') {
        if port.parse::<u16>().is_ok() {
            let proto = parse_proto(proto)?;
            return Ok(Some(vec![rule_with_port(action, port.to_string(), Some(proto))]));
        }
    }
    if let Some(profile) = apps::load(tok)? {
        return Ok(Some(expand_profile(action, &profile)?));
    }
    Ok(None)
}

fn expand_profile(action: Action, profile: &AppProfile) -> Result<Vec<UserRule>> {
    let proto = match profile.proto.as_str() {
        "" | "any" => None,
        other => Some(parse_proto(other)?),
    };
    let ports: Vec<String> =
        profile.ports.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
    if ports.is_empty() {
        bail!("app profile `{}` has no ports", profile.name);
    }
    Ok(ports.into_iter().map(|port| rule_with_port(action, port, proto)).collect())
}

fn rule_with_port(action: Action, port: String, proto: Option<Protocol>) -> UserRule {
    UserRule {
        direction: Direction::In,
        action,
        iface: None,
        proto,
        src: None,
        dst: None,
        src_port: None,
        dst_port: Some(port),
    }
}

fn parse_full_grammar(action: Action, tokens: &[String]) -> Result<UserRule> {
    let mut rule = UserRule {
        direction: Direction::In,
        action,
        iface: None,
        proto: None,
        src: None,
        dst: None,
        src_port: None,
        dst_port: None,
    };

    let mut iter = tokens.iter().peekable();

    let mut dir_set = false;
    let (mut from_seen, mut to_seen) = (false, false);

    while let Some(tok) = iter.peek() {
        let dir = match tok.as_str() {
            "in" => Direction::In,
            "out" => Direction::Out,
            _ => break,
        };
        if dir_set {
            bail!("direction specified more than once");
        }
        rule.direction = dir;
        dir_set = true;
        iter.next();
    }

    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "on" => {
                if rule.iface.is_some() {
                    bail!("`on` specified more than once");
                }
                let iface = iter.next().context("expected interface after `on`")?;
                validate_iface(iface)?;
                rule.iface = Some(iface.clone());
            }
            "from" => {
                if from_seen {
                    bail!("`from` specified more than once");
                }
                from_seen = true;
                let cidr = iter.next().context("expected address after `from`")?;
                if cidr != "any" {
                    rule.src = Some(cidr.clone());
                }
                if iter.peek().is_some_and(|n| n.as_str() == "port") {
                    iter.next();
                    let p = iter.next().context("expected port after `port`")?;
                    rule.src_port = Some(p.clone());
                }
            }
            "to" => {
                if to_seen {
                    bail!("`to` specified more than once");
                }
                to_seen = true;
                let cidr = iter.next().context("expected address after `to`")?;
                if cidr != "any" {
                    rule.dst = Some(cidr.clone());
                }
                if iter.peek().is_some_and(|n| n.as_str() == "port") {
                    iter.next();
                    let p = iter.next().context("expected port after `port`")?;
                    set_dst_port(&mut rule, p)?;
                }
            }
            "port" => {
                let p = iter.next().context("expected port after `port`")?;
                set_dst_port(&mut rule, p)?;
            }
            "proto" => {
                if rule.proto.is_some() {
                    bail!("`proto` specified more than once");
                }
                let p = iter.next().context("expected protocol after `proto`")?;
                rule.proto = Some(parse_proto(p)?);
            }
            other => bail!("unexpected token `{other}`"),
        }
    }

    Ok(rule)
}

fn set_dst_port(rule: &mut UserRule, port: &str) -> Result<()> {
    if rule.dst_port.is_some() {
        bail!("destination port specified more than once");
    }
    rule.dst_port = Some(port.to_string());
    Ok(())
}

fn parse_proto(s: &str) -> Result<Protocol> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        "any" => Ok(Protocol::Any),
        other => bail!("unknown protocol `{other}`"),
    }
}

fn validate_iface(name: &str) -> Result<()> {
    if !moatd_common::valid_iface_name(name) {
        bail!("invalid interface name `{name}`");
    }
    Ok(())
}

pub fn parse_default_args(args: &[String]) -> Result<(Direction, Action)> {
    if args.len() != 2 {
        bail!("usage: moatd default <allow|deny|reject> <incoming|outgoing>");
    }
    let action = match args[0].to_ascii_lowercase().as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        "reject" => Action::Reject,
        other => bail!("unknown action `{other}`"),
    };
    let direction = match args[1].to_ascii_lowercase().as_str() {
        "in" | "incoming" => Direction::In,
        "out" | "outgoing" => Direction::Out,
        other => bail!("unknown direction `{other}`"),
    };
    Ok((direction, action))
}

#[cfg(test)]
mod tests {
    use super::{parse_default_args, parse_rule_spec, Action, Direction, Protocol};

    fn tok(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn shorthand_bare_port() {
        let rules = parse_rule_spec(Action::Allow, &tok("22")).unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.dst_port.as_deref(), Some("22"));
        assert!(r.proto.is_none());
        assert_eq!(r.action, Action::Allow);
        assert_eq!(r.direction, Direction::In);
    }

    #[test]
    fn shorthand_port_with_proto() {
        let rules = parse_rule_spec(Action::Allow, &tok("53/udp")).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dst_port.as_deref(), Some("53"));
        assert_eq!(rules[0].proto, Some(Protocol::Udp));
    }

    #[test]
    fn full_grammar_with_iface_and_cidr() {
        let rules = parse_rule_spec(
            Action::Deny,
            &tok("in on tailscale0 from 10.0.0.0/8 to any port 22 proto tcp"),
        )
        .unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.direction, Direction::In);
        assert_eq!(r.iface.as_deref(), Some("tailscale0"));
        assert_eq!(r.src.as_deref(), Some("10.0.0.0/8"));
        assert!(r.dst.is_none());
        assert_eq!(r.dst_port.as_deref(), Some("22"));
        assert_eq!(r.proto, Some(Protocol::Tcp));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_rule_spec(Action::Allow, &[]).is_err());
    }

    #[test]
    fn rejects_unknown_token() {
        // "oops" isn't a known token AND isn't an app profile -> error.
        assert!(parse_rule_spec(Action::Allow, &tok("port 22 oops")).is_err());
    }

    #[test]
    fn rejects_duplicate_and_conflicting_tokens() {
        assert!(parse_rule_spec(Action::Allow, &tok("in out port 22")).is_err());
        assert!(parse_rule_spec(Action::Allow, &tok("from 1.1.1.1 from 2.2.2.2 port 22")).is_err());
        assert!(parse_rule_spec(Action::Allow, &tok("port 22 port 80")).is_err());
        assert!(parse_rule_spec(Action::Allow, &tok("to any port 22 port 80")).is_err());
        assert!(parse_rule_spec(Action::Allow, &tok("on eth0 on eth1 port 22")).is_err());
        assert!(parse_rule_spec(Action::Allow, &tok("port 22 proto tcp proto udp")).is_err());
    }

    #[test]
    fn out_direction_and_dst() {
        let rules =
            parse_rule_spec(Action::Allow, &tok("out to 8.8.8.8 port 53 proto udp")).unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.direction, Direction::Out);
        assert_eq!(r.dst.as_deref(), Some("8.8.8.8"));
        assert_eq!(r.dst_port.as_deref(), Some("53"));
    }

    #[test]
    fn default_args() {
        let (d, a) = parse_default_args(&tok("deny incoming")).unwrap();
        assert_eq!(d, Direction::In);
        assert_eq!(a, Action::Deny);
    }

    #[test]
    fn v6_cidr_in_grammar() {
        let rules =
            parse_rule_spec(Action::Deny, &tok("in from fe80::/10 to any port 80 proto tcp"))
                .unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.src.as_deref(), Some("fe80::/10"));
        assert_eq!(r.dst_port.as_deref(), Some("80"));
        assert_eq!(r.proto, Some(Protocol::Tcp));
    }
}
