use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{ring_buf::RingBuf, Array, MapData},
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags},
    Ebpf,
};
use clap::{Parser, Subcommand};
use moatd_common::control::{
    Action, Direction, Request, Response, StatusReport, UserRule, SOCKET_PATH,
};
use moatd_common::{
    DropEvent, GlobalConfig, Rule, FAMILY_V4, POLICY_IN, POLICY_OUT, PROTO_ICMP, PROTO_ICMPV6,
    PROTO_TCP, PROTO_UDP, RULES_MAX, RULE_ID_DEFAULT, SCHEMA_VERSION,
};
use tokio::io::{unix::AsyncFd, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use moatd::parser;
use moatd::store::{self, OnDisk, RULES_FILE};
use moatd::wire;

const XDP_PROG: &str = "moat_ingress";
const TC_PROG: &str = "moat_egress";
const MAX_FRAME_BYTES: usize = 1 << 20;

#[derive(Parser)]
#[command(name = "moatd", version, about = "ufw-style eBPF firewall (CLI + daemon)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the firewall daemon (invoked by the systemd unit).
    Daemon,
    /// Enable and start the moatd service.
    Enable,
    /// Disable and stop the moatd service.
    Disable,
    /// Show firewall status, defaults and attached interfaces.
    Status,
    /// List numbered rules.
    List,
    /// Add an allow rule, e.g. `moatd allow 22/tcp` or
    /// `moatd allow in on tailscale0 to any port 22 proto tcp`.
    Allow {
        #[arg(trailing_var_arg = true, num_args = 1..)]
        spec: Vec<String>,
    },
    /// Add a deny rule.
    Deny {
        #[arg(trailing_var_arg = true, num_args = 1..)]
        spec: Vec<String>,
    },
    /// Add a reject rule (currently treated as deny in XDP, phase 5 adds true reject).
    Reject {
        #[arg(trailing_var_arg = true, num_args = 1..)]
        spec: Vec<String>,
    },
    /// Set default policy, e.g. `moatd default deny incoming`.
    Default {
        #[arg(trailing_var_arg = true, num_args = 2)]
        args: Vec<String>,
    },
    /// Delete rule N (1-based).
    Delete { index: u32 },
    /// Reset all rules and defaults to allow-all.
    Reset,
    /// Toggle block logging to journald.
    Logging { value: String },
    /// Ping the daemon.
    Ping,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Daemon => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?;
            rt.block_on(run_daemon())
        }
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

// =====================================================================
// CLI dispatch (sync, talks to the daemon over /run/moatd/control.sock)
// =====================================================================

fn enable() -> Result<()> {
    run_systemctl(&["enable", "--now", "moatd"])?;
    println!("moatd enabled");
    Ok(())
}

fn disable() -> Result<()> {
    run_systemctl(&["disable", "--now", "moatd"])?;
    println!("moatd disabled");
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

fn add(action: Action, spec: &[String]) -> Result<()> {
    let rule = parser::parse_rule_spec(action, spec)?;
    simple_ok(call(&Request::AddRule(rule))?, "rule added")
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

fn run_systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl").args(args).status().context("invoking systemctl")?;
    if !status.success() {
        anyhow::bail!("systemctl {} failed (exit {})", args.join(" "), status);
    }
    Ok(())
}

fn call(req: &Request) -> Result<Response> {
    let mut stream = StdUnixStream::connect(SOCKET_PATH)
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

// =====================================================================
// Daemon
// =====================================================================

struct Maps {
    rules: Array<MapData, Rule>,
    default_policy: Array<MapData, u8>,
    config: Array<MapData, GlobalConfig>,
}

struct DaemonState {
    attached_interfaces: Vec<String>,
    on_disk: OnDisk,
    maps: Maps,
}

async fn run_daemon() -> Result<()> {
    init_daemon_tracing();

    let ebpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/moatd-bpf"));
    let mut ebpf = Ebpf::load(ebpf_bytes).context("loading eBPF object")?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!(error = %e, "eBPF logger init failed");
    }

    let interfaces = enumerate_interfaces()?;

    {
        let prog: &mut Xdp = ebpf
            .program_mut(XDP_PROG)
            .with_context(|| format!("program {XDP_PROG} not found"))?
            .try_into()?;
        prog.load().context("loading XDP program into kernel")?;
        for iface in &interfaces {
            match attach_xdp_with_fallback(prog, iface) {
                Ok(mode) => info!(iface, mode, "XDP attached"),
                Err(e) => warn!(iface, error = %e, "XDP attach failed"),
            }
        }
    }

    let mut attached = Vec::new();
    {
        let tc_prog: &mut SchedClassifier = ebpf
            .program_mut(TC_PROG)
            .with_context(|| format!("program {TC_PROG} not found"))?
            .try_into()?;
        tc_prog.load().context("loading TC program into kernel")?;
        for iface in &interfaces {
            let _ = tc::qdisc_add_clsact(iface);
            match tc_prog.attach(iface, TcAttachType::Egress) {
                Ok(_) => {
                    info!(iface, "TC egress attached");
                    attached.push(iface.clone());
                }
                Err(e) => warn!(iface, error = %e, "TC egress attach failed"),
            }
        }
    }

    let maps = take_maps(&mut ebpf)?;

    match setup_event_drainer(&mut ebpf) {
        Ok(fd) => {
            tokio::spawn(drain_events(fd));
            info!("block-event log drainer started");
        }
        Err(e) => warn!(error = %e, "block-event logging unavailable"),
    }

    // Note: this needs to run AFTER initial sync_all so the watcher's
    // comparison baseline is established below.

    let on_disk = match store::load(RULES_FILE) {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, path = RULES_FILE, "rules file unreadable, using defaults");
            OnDisk::default()
        }
    };

    let mut state = DaemonState { attached_interfaces: attached, on_disk, maps };
    sync_all(&mut state).context("initial sync to BPF maps")?;

    let shared = Arc::new(Mutex::new(state));

    tokio::spawn(watch_interfaces(Arc::clone(&shared)));

    let listener = bind_control_socket().context("binding control socket")?;
    info!(path = SOCKET_PATH, "control socket listening");

    if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        warn!(error = %e, "sd_notify ready failed");
    }

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let shared = Arc::clone(&shared);
                        tokio::spawn(async move {
                            if let Err(e) = serve_client(stream, shared).await {
                                warn!(error = %e, "control client error");
                            }
                        });
                    }
                    Err(e) => warn!(error = %e, "accept failed"),
                }
            }
            _ = sigterm.recv() => {
                info!("SIGTERM, shutting down");
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT, shutting down");
                break;
            }
        }
    }

    let _ = ebpf;
    Ok(())
}

fn init_daemon_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = || EnvFilter::try_from_env("MOAT_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    // MOAT_LOG_STDOUT=1 forces stderr/stdout tracing instead of journald, which
    // is useful in tests where the host's journald socket is reachable from
    // inside an `ip netns exec` but we want to inspect logs by reading the
    // process's stdout/stderr capture file.
    let force_stdout = std::env::var_os("MOAT_LOG_STDOUT").is_some();
    if !force_stdout {
        if let Ok(journald) = tracing_journald::layer() {
            tracing_subscriber::registry().with(filter()).with(journald).init();
            return;
        }
    }
    tracing_subscriber::registry().with(filter()).with(tracing_subscriber::fmt::layer()).init();
}

fn enumerate_interfaces() -> Result<Vec<String>> {
    if let Ok(val) = std::env::var("MOAT_INTERFACES") {
        let ifs: Vec<String> =
            val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if ifs.is_empty() {
            anyhow::bail!("MOAT_INTERFACES is set but empty");
        }
        return Ok(ifs);
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net").context("reading /sys/class/net")? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if is_skipped_iface(&name) {
            continue;
        }
        out.push(name);
    }
    Ok(out)
}

fn is_skipped_iface(name: &str) -> bool {
    name == "lo"
        || name.starts_with("docker")
        || name.starts_with("virbr")
        || name.starts_with("br-")
        || name.starts_with("veth")
        || name.starts_with("ipvl")
}

fn attach_xdp_with_fallback(prog: &mut Xdp, iface: &str) -> Result<&'static str> {
    if prog.attach(iface, XdpFlags::DRV_MODE).is_ok() {
        return Ok("drv");
    }
    prog.attach(iface, XdpFlags::SKB_MODE).context("XDP attach (SKB_MODE)")?;
    Ok("skb")
}

fn take_maps(ebpf: &mut Ebpf) -> Result<Maps> {
    let rules: Array<MapData, Rule> =
        Array::try_from(ebpf.take_map("RULES").context("RULES map missing")?)?;
    let default_policy: Array<MapData, u8> =
        Array::try_from(ebpf.take_map("DEFAULT_POLICY").context("DEFAULT_POLICY map missing")?)?;
    let config: Array<MapData, GlobalConfig> =
        Array::try_from(ebpf.take_map("CONFIG").context("CONFIG map missing")?)?;
    Ok(Maps { rules, default_policy, config })
}

fn sync_all(state: &mut DaemonState) -> Result<()> {
    sync_defaults(state)?;
    sync_config(state)?;
    sync_rules(state)?;
    Ok(())
}

fn sync_defaults(state: &mut DaemonState) -> Result<()> {
    state.maps.default_policy.set(POLICY_IN, wire::action_byte(state.on_disk.default_in), 0)?;
    state.maps.default_policy.set(POLICY_OUT, wire::action_byte(state.on_disk.default_out), 0)?;
    Ok(())
}

fn sync_config(state: &mut DaemonState) -> Result<()> {
    let cfg = GlobalConfig {
        logging_enabled: u8::from(state.on_disk.logging_enabled),
        log_level: 0,
        _pad: [0; 6],
    };
    state.maps.config.set(0, cfg, 0)?;
    Ok(())
}

fn sync_rules(state: &mut DaemonState) -> Result<()> {
    let mut wire_rules: Vec<Rule> = Vec::with_capacity(state.on_disk.rules.len());
    for ur in &state.on_disk.rules {
        let iface_ifindex = wire::resolve_iface(ur.iface.as_deref());
        if let Some(name) = ur.iface.as_deref() {
            if iface_ifindex == moatd_common::IFACE_ABSENT {
                warn!(iface = name, "interface not present; rule disabled until it appears");
            }
        }
        wire_rules.push(wire::build_wire_rule(ur, iface_ifindex)?);
    }

    for i in 0..RULES_MAX {
        let slot = wire_rules.get(i as usize).copied().unwrap_or_else(wire::empty_wire_rule);
        state.maps.rules.set(i, slot, 0)?;
    }
    Ok(())
}

fn bind_control_socket() -> Result<UnixListener> {
    let path = Path::new(SOCKET_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
    }
    if path.exists() {
        match StdUnixStream::connect(path) {
            Ok(_) => {
                anyhow::bail!("another moatd is already running and bound to {}", path.display())
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(path).context("removing stale socket")?;
            }
            Err(e) => return Err(anyhow::anyhow!("probing existing socket: {e}")),
        }
    }
    let prev = unsafe { libc::umask(0o117) };
    let listener_result = UnixListener::bind(path);
    unsafe { libc::umask(prev) };
    let listener = listener_result?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

async fn serve_client(mut stream: UnixStream, shared: Arc<Mutex<DaemonState>>) -> Result<()> {
    let req = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream))
        .await
        .map_err(|_| anyhow::anyhow!("client read timed out"))??;
    let req: Request = serde_json::from_slice(&req).context("decoding request")?;
    let resp = dispatch(req, &shared).await;
    let resp_bytes = serde_json::to_vec(&resp)?;
    tokio::time::timeout(Duration::from_secs(5), write_frame(&mut stream, &resp_bytes))
        .await
        .map_err(|_| anyhow::anyhow!("client write timed out"))??;
    Ok(())
}

async fn dispatch(req: Request, shared: &Arc<Mutex<DaemonState>>) -> Response {
    let mut state = shared.lock().await;
    match req {
        Request::Ping => Response::Pong,
        Request::Status => Response::Status(StatusReport {
            active: true,
            attached_interfaces: state.attached_interfaces.clone(),
            rules: state.on_disk.rules.len() as u32,
            schema_version: SCHEMA_VERSION,
            default_in: state.on_disk.default_in,
            default_out: state.on_disk.default_out,
            logging_enabled: state.on_disk.logging_enabled,
        }),
        Request::ListRules => Response::Rules(state.on_disk.rules.clone()),
        Request::AddRule(rule) => to_response(add_rule(&mut state, rule)),
        Request::DeleteRule(idx) => to_response(delete_rule(&mut state, idx)),
        Request::SetDefault { direction, action } => {
            to_response(set_default(&mut state, direction, action))
        }
        Request::SetLogging { enabled } => to_response(set_logging(&mut state, enabled)),
        Request::Reset => to_response(reset(&mut state)),
    }
}

fn to_response(r: Result<()>) -> Response {
    match r {
        Ok(()) => Response::Ok,
        Err(e) => Response::Err(format!("{e:#}")),
    }
}

fn add_rule(state: &mut DaemonState, rule: UserRule) -> Result<()> {
    if state.on_disk.rules.len() >= RULES_MAX as usize {
        anyhow::bail!("rule limit ({RULES_MAX}) reached");
    }
    if let Some(name) = rule.iface.as_deref() {
        validate_iface_name(name)?;
    }
    state.on_disk.rules.push(rule);
    persist_and_sync(state)
}

fn validate_iface_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 {
        anyhow::bail!("invalid interface name `{name}`");
    }
    if name.bytes().any(|b| b == b'/' || b == b' ' || b == 0) {
        anyhow::bail!("invalid interface name `{name}`");
    }
    Ok(())
}

fn delete_rule(state: &mut DaemonState, one_based_idx: u32) -> Result<()> {
    if one_based_idx == 0 {
        anyhow::bail!("rule index is 1-based");
    }
    let idx = (one_based_idx - 1) as usize;
    if idx >= state.on_disk.rules.len() {
        anyhow::bail!("no rule at index {one_based_idx}");
    }
    state.on_disk.rules.remove(idx);
    persist_and_sync(state)
}

fn set_default(state: &mut DaemonState, dir: Direction, action: Action) -> Result<()> {
    match dir {
        Direction::In => state.on_disk.default_in = action,
        Direction::Out => state.on_disk.default_out = action,
    }
    persist_and_sync(state)
}

fn set_logging(state: &mut DaemonState, enabled: bool) -> Result<()> {
    state.on_disk.logging_enabled = enabled;
    persist_and_sync(state)
}

fn reset(state: &mut DaemonState) -> Result<()> {
    state.on_disk.rules.clear();
    state.on_disk.default_in = Action::Allow;
    state.on_disk.default_out = Action::Allow;
    state.on_disk.logging_enabled = false;
    persist_and_sync(state)
}

fn persist_and_sync(state: &mut DaemonState) -> Result<()> {
    store::save(RULES_FILE, &state.on_disk)?;
    sync_all(state)
}

async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).context("payload exceeds u32")?.to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

// =====================================================================
// Link watcher: polls /sys/class/net every 2s and re-syncs the RULES
// map when an interface referenced by a rule appears, disappears, or
// changes operstate. This is a lightweight stand-in for netlink
// subscription; reactivity is bounded by the poll interval but the
// behaviour is identical from the rule's point of view.
// =====================================================================

const IFACE_POLL_INTERVAL: Duration = Duration::from_secs(2);

async fn watch_interfaces(shared: Arc<Mutex<DaemonState>>) {
    let mut tick = tokio::time::interval(IFACE_POLL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last = wire::iface_snapshot();
    loop {
        tick.tick().await;
        let current = wire::iface_snapshot();
        if current == last {
            continue;
        }
        let changed: Vec<String> = current
            .iter()
            .filter(|(k, v)| last.get(*k) != Some(*v))
            .chain(last.iter().filter(|(k, _)| !current.contains_key(*k)))
            .map(|(k, _)| k.clone())
            .collect();
        let touches_rules = {
            let s = shared.lock().await;
            s.on_disk
                .rules
                .iter()
                .any(|r| r.iface.as_deref().is_some_and(|name| changed.iter().any(|c| c == name)))
        };
        if touches_rules {
            info!(?changed, "interface change touched a rule, re-syncing");
            let mut s = shared.lock().await;
            if let Err(e) = sync_rules(&mut s) {
                warn!(error = %e, "iface change sync failed");
            }
        }
        last = current;
    }
}

// =====================================================================
// Block-event logging: drains the EVENTS ringbuf, dedupes in a 1s
// sliding window, and emits one tracing event per (src,dst_port,proto,
// rule,iface) bucket so journald doesn't get flooded.
// =====================================================================

fn setup_event_drainer(ebpf: &mut Ebpf) -> Result<AsyncFd<RingBuf<MapData>>> {
    let map = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
    let rb = RingBuf::try_from(map).context("EVENTS map wrong type")?;
    AsyncFd::new(rb).context("registering EVENTS fd with tokio")
}

async fn drain_events(mut events: AsyncFd<RingBuf<MapData>>) {
    let mut dedupe = DedupeWindow::default();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => dedupe.flush(),
            r = events.readable_mut() => {
                let Ok(mut guard) = r else { continue };
                while let Some(item) = guard.get_inner_mut().next() {
                    let bytes: &[u8] = &item;
                    if bytes.len() != std::mem::size_of::<DropEvent>() {
                        continue;
                    }
                    let event: DropEvent = bytemuck::pod_read_unaligned(bytes);
                    dedupe.record(event);
                }
                guard.clear_ready();
            }
        }
    }
}

#[derive(Default)]
struct DedupeWindow {
    entries: HashMap<DedupeKey, DedupeAccum>,
}

#[derive(Eq, PartialEq, Hash, Clone, Copy)]
struct DedupeKey {
    family: u8,
    proto: u8,
    src: [u8; 16],
    dst_port: u16,
    ifindex: u32,
    rule_id: u32,
}

struct DedupeAccum {
    count: u32,
    sample: DropEvent,
}

impl DedupeWindow {
    fn record(&mut self, event: DropEvent) {
        let key = DedupeKey {
            family: event.family,
            proto: event.proto,
            src: event.src,
            dst_port: event.dst_port,
            ifindex: event.ifindex,
            rule_id: event.rule_id,
        };
        self.entries
            .entry(key)
            .and_modify(|a| a.count += 1)
            .or_insert(DedupeAccum { count: 1, sample: event });
    }

    fn flush(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        for (_, accum) in self.entries.drain() {
            let e = &accum.sample;
            let src = format_addr(e.family, &e.src);
            let dst = format_addr(e.family, &e.dst);
            let proto = proto_name(e.proto);
            let rule = if e.rule_id == RULE_ID_DEFAULT {
                "default".to_string()
            } else {
                format!("rule #{}", e.rule_id + 1)
            };
            let iface = iface_name(e.ifindex).unwrap_or_else(|| format!("if{}", e.ifindex));
            let plural = if accum.count == 1 { "" } else { "s" };
            info!(
                target: "moatd::block",
                "BLOCK src={src} dst={dst}:{port}/{proto} on {iface} ({rule}, {count} hit{plural} in 1s)",
                src = src,
                dst = dst,
                port = e.dst_port,
                proto = proto,
                iface = iface,
                rule = rule,
                count = accum.count,
                plural = plural,
            );
        }
    }
}

fn format_addr(family: u8, bytes: &[u8; 16]) -> String {
    if family == FAMILY_V4 {
        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
    } else {
        Ipv6Addr::from(*bytes).to_string()
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        PROTO_ICMP => "icmp",
        PROTO_ICMPV6 => "icmpv6",
        _ => "any",
    }
}

fn iface_name(ifindex: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr().cast()) };
    if ptr.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) };
    cstr.to_str().ok().map(String::from)
}
