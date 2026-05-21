use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use moat_common::control::{Request, Response, SOCKET_PATH};

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
    /// Show firewall status and attached interfaces
    Status,
    /// Reload rules from /etc/moat/rules.toml (phase 2+)
    Reload,
    /// Ping the daemon
    Ping,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Enable => enable(),
        Cmd::Disable => disable(),
        Cmd::Status => status(),
        Cmd::Reload => reload(),
        Cmd::Ping => ping(),
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
    match call(Request::Status)? {
        Response::Status(s) => {
            println!("Status:    {}", if s.active { "active" } else { "inactive" });
            println!("Schema:    v{}", s.schema_version);
            println!("Rules:     {}", s.rules);
            if s.attached_interfaces.is_empty() {
                println!("Interfaces: (none)");
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

fn reload() -> Result<()> {
    println!("reload: not implemented yet (phase 2)");
    Ok(())
}

fn ping() -> Result<()> {
    match call(Request::Ping)? {
        Response::Pong => {
            println!("pong");
            Ok(())
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .context("invoking systemctl")?;
    if !status.success() {
        anyhow::bail!("systemctl {} failed (exit {})", args.join(" "), status);
    }
    Ok(())
}

fn call(req: Request) -> Result<Response> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .with_context(|| format!("connecting to {SOCKET_PATH} (is moatd running?)"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let bytes = serde_json::to_vec(&req)?;
    let len = u32::try_from(bytes.len())
        .context("request too large")?
        .to_be_bytes();
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
