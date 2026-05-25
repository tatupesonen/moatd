use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, MapData},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use moat_common::control::{Action, Direction, Request, Response, StatusReport, UserRule, SOCKET_PATH};
use moat_common::{GlobalConfig, Rule, POLICY_IN, POLICY_OUT, RULES_MAX, SCHEMA_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use moat::store::{self, OnDisk, RULES_FILE};
use moat::wire;

const PROG_NAME: &str = "moat_ingress";
const MAX_FRAME_BYTES: usize = 1 << 20;

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

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    init_tracing();

    let ebpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/moat"));
    let mut ebpf = Ebpf::load(ebpf_bytes).context("loading eBPF object")?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!(error = %e, "eBPF logger init failed");
    }

    let prog: &mut Xdp = ebpf
        .program_mut(PROG_NAME)
        .with_context(|| format!("program {PROG_NAME} not found"))?
        .try_into()?;
    prog.load().context("loading XDP program into kernel")?;

    let interfaces = enumerate_interfaces()?;
    let mut attached = Vec::new();
    for iface in &interfaces {
        match attach_xdp_with_fallback(prog, iface) {
            Ok(mode) => {
                info!(iface, mode, "XDP attached");
                attached.push(iface.clone());
            }
            Err(e) => warn!(iface, error = %e, "XDP attach failed"),
        }
    }

    let maps = take_maps(&mut ebpf)?;

    let on_disk = match store::load(RULES_FILE) {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, path = RULES_FILE, "rules file unreadable, using defaults");
            OnDisk::default()
        }
    };

    let mut state = DaemonState {
        attached_interfaces: attached,
        on_disk,
        maps,
    };
    sync_all(&mut state).context("initial sync to BPF maps")?;

    let shared = Arc::new(Mutex::new(state));

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

fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = || EnvFilter::try_from_env("MOAT_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    if let Ok(journald) = tracing_journald::layer() {
        tracing_subscriber::registry()
            .with(filter())
            .with(journald)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter())
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}

fn enumerate_interfaces() -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net").context("reading /sys/class/net")? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name == "lo" || name.starts_with("docker") || name.starts_with("virbr") {
            continue;
        }
        out.push(name);
    }
    Ok(out)
}

fn attach_xdp_with_fallback(prog: &mut Xdp, iface: &str) -> Result<&'static str> {
    match prog.attach(iface, XdpFlags::DRV_MODE) {
        Ok(_) => Ok("drv"),
        Err(_) => {
            prog.attach(iface, XdpFlags::SKB_MODE)
                .context("XDP attach (SKB_MODE)")?;
            Ok("skb")
        }
    }
}

fn take_maps(ebpf: &mut Ebpf) -> Result<Maps> {
    let rules: Array<MapData, Rule> = Array::try_from(
        ebpf.take_map("RULES").context("RULES map missing")?,
    )?;
    let default_policy: Array<MapData, u8> = Array::try_from(
        ebpf.take_map("DEFAULT_POLICY").context("DEFAULT_POLICY map missing")?,
    )?;
    let config: Array<MapData, GlobalConfig> = Array::try_from(
        ebpf.take_map("CONFIG").context("CONFIG map missing")?,
    )?;
    Ok(Maps {
        rules,
        default_policy,
        config,
    })
}

fn sync_all(state: &mut DaemonState) -> Result<()> {
    sync_defaults(state)?;
    sync_config(state)?;
    sync_rules(state)?;
    Ok(())
}

fn sync_defaults(state: &mut DaemonState) -> Result<()> {
    state
        .maps
        .default_policy
        .set(POLICY_IN, wire::action_byte(state.on_disk.default_in), 0)?;
    state
        .maps
        .default_policy
        .set(POLICY_OUT, wire::action_byte(state.on_disk.default_out), 0)?;
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
    let priorities: Vec<Rule> = state
        .on_disk
        .rules
        .iter()
        .enumerate()
        .map(|(i, ur)| {
            let iface_ifindex = wire::resolve_iface(ur.iface.as_deref());
            wire::build_wire_rule(ur, i as u32, iface_ifindex)
        })
        .collect::<Result<Vec<_>>>()?;

    for i in 0..RULES_MAX {
        let slot = priorities
            .get(i as usize)
            .copied()
            .unwrap_or_else(wire::empty_wire_rule);
        state.maps.rules.set(i, slot, 0)?;
    }
    Ok(())
}

fn bind_control_socket() -> Result<UnixListener> {
    let path = Path::new(SOCKET_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    if path.exists() {
        std::fs::remove_file(path).context("removing stale socket")?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

async fn serve_client(mut stream: UnixStream, shared: Arc<Mutex<DaemonState>>) -> Result<()> {
    let req = read_frame(&mut stream).await?;
    let req: Request = serde_json::from_slice(&req).context("decoding request")?;
    let resp = dispatch(req, &shared).await;
    let resp_bytes = serde_json::to_vec(&resp)?;
    write_frame(&mut stream, &resp_bytes).await?;
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
    state.on_disk.rules.push(rule);
    persist_and_sync(state)
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
    let len = u32::try_from(payload.len())
        .context("payload exceeds u32")?
        .to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

