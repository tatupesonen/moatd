use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use moatd_common::control::{Action, Request, Response, UserRule, SOCKET_PATH};

use moatd::parser;

const MAX_FRAME_BYTES: usize = 1 << 20;

#[derive(Parser)]
#[command(name = "moat", version, about = "ufw-style eBPF firewall")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enable and start the moatd service
    Enable,
    /// Disable and stop the moatd service
    Disable,
    /// Show firewall status, defaults and attached interfaces
    Status,
    /// List numbered rules
    List,
    /// Add an allow rule, e.g. `moat allow 22/tcp` or `moat allow in on tailscale0 to any port 22 proto tcp`
    Allow {
        #[arg(trailing_var_arg = true, num_args = 1..)]
        spec: Vec<String>,
    },
    /// Add a deny rule
    Deny {
        #[arg(trailing_var_arg = true, num_args = 1..)]
        spec: Vec<String>,
    },
    /// Add a reject rule (currently treated as deny in XDP, phase 5 adds true reject)
    Reject {
        #[arg(trailing_var_arg = true, num_args = 1..)]
        spec: Vec<String>,
    },
    /// Set default policy, e.g. `moat default deny incoming`
    Default {
        #[arg(trailing_var_arg = true, num_args = 2)]
        args: Vec<String>,
    },
    /// Delete rule N (1-based)
    Delete { index: u32 },
    /// Reset all rules and defaults to allow-all
    Reset,
    /// Toggle block logging to journald (phase 5)
    Logging { value: String },
    /// Ping the daemon
    Ping,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Enable => enable(),
        Cmd::Disable => disable(),
        Cmd::Status => status(),
        Cmd::List => list(),
        Cmd::Allow { spec } => add(Action::Allow, &spec),
        Cmd::Deny { spec } => add(Action::Deny, &spec),
        Cmd::Reject { spec } => add(Action::Reject, &spec),
        Cmd::Default { args } => {
            let (direction, action) = parser::parse_default_args(&args)?;
            simple_ok(call(&Request::SetDefault { direction, action })?, "default updated")
        }
        Cmd::Delete { index } => simple_ok(call(&Request::DeleteRule(index))?, "rule deleted"),
        Cmd::Reset => simple_ok(call(&Request::Reset)?, "firewall reset"),
        Cmd::Logging { value } => {
            let enabled = match value.as_str() {
                "on" | "true" | "yes" => true,
                "off" | "false" | "no" => false,
                _ => anyhow::bail!("logging value must be on/off"),
            };
            simple_ok(call(&Request::SetLogging { enabled })?, "logging updated")
        }
        Cmd::Ping => ping(),
    }
}

fn add(action: Action, spec: &[String]) -> Result<()> {
    let rule = parser::parse_rule_spec(action, spec)?;
    simple_ok(call(&Request::AddRule(rule))?, "rule added")
}

fn simple_ok(resp: Response, msg: &str) -> Result<()> {
    match resp {
        Response::Ok => {
            println!("{msg}");
            Ok(())
        }
        Response::Err(e) => anyhow::bail!("daemon error: {e}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

fn enable() -> Result<()> {
    run_systemctl(&["enable", "--now", "moatd"])?;
    println!("moat enabled");
    Ok(())
}

fn disable() -> Result<()> {
    run_systemctl(&["disable", "--now", "moatd"])?;
    println!("moat disabled");
    Ok(())
}

fn status() -> Result<()> {
    match call(&Request::Status)? {
        Response::Status(s) => {
            println!("Status:      {}", if s.active { "active" } else { "inactive" });
            println!("Schema:      v{}", s.schema_version);
            println!("Default in:  {:?}", s.default_in);
            println!("Default out: {:?}", s.default_out);
            println!("Logging:     {}", if s.logging_enabled { "on" } else { "off" });
            println!("Rules:       {}", s.rules);
            if s.attached_interfaces.is_empty() {
                println!("Interfaces:  (none)");
            } else {
                println!("Interfaces:");
                for i in &s.attached_interfaces {
                    println!("  {i}");
                }
            }
            Ok(())
        }
        Response::Err(e) => anyhow::bail!("daemon error: {e}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

fn list() -> Result<()> {
    match call(&Request::ListRules)? {
        Response::Rules(rs) => {
            if rs.is_empty() {
                println!("(no rules)");
                return Ok(());
            }
            for (i, r) in rs.iter().enumerate() {
                println!("[{}] {}", i + 1, render_rule(r));
            }
            Ok(())
        }
        Response::Err(e) => anyhow::bail!("daemon error: {e}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

fn render_rule(r: &UserRule) -> String {
    let mut parts = vec![format!("{:?} {:?}", r.action, r.direction).to_lowercase()];
    if let Some(iface) = &r.iface {
        parts.push(format!("on {iface}"));
    }
    if let Some(src) = &r.src {
        parts.push(format!("from {src}"));
    }
    if let Some(sp) = &r.src_port {
        parts.push(format!("src port {sp}"));
    }
    if let Some(dst) = &r.dst {
        parts.push(format!("to {dst}"));
    }
    if let Some(dp) = &r.dst_port {
        parts.push(format!("port {dp}"));
    }
    if let Some(proto) = r.proto {
        parts.push(format!("proto {proto:?}").to_lowercase());
    }
    parts.join(" ")
}

fn ping() -> Result<()> {
    match call(&Request::Ping)? {
        Response::Pong => {
            println!("pong");
            Ok(())
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl").args(args).status().context("invoking systemctl")?;
    if !status.success() {
        anyhow::bail!("systemctl {} failed (exit {})", args.join(" "), status);
    }
    Ok(())
}

fn call(req: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .with_context(|| format!("connecting to {SOCKET_PATH} (is moatd running?)"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let bytes = serde_json::to_vec(req)?;
    let len = u32::try_from(bytes.len()).context("request too large")?.to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&bytes)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_FRAME_BYTES {
        anyhow::bail!("response too large: {resp_len} bytes");
    }
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).context("decoding response")
}
