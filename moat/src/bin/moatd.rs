use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use moat_common::control::{Request, Response, StatusReport, SOCKET_PATH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const PROG_NAME: &str = "moat_ingress";
const MAX_FRAME_BYTES: usize = 1 << 20;

#[derive(Default)]
struct DaemonState {
    attached_interfaces: Vec<String>,
    rules: u32,
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
        .with_context(|| format!("program {PROG_NAME} not found in object"))?
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

    let state = Arc::new(RwLock::new(DaemonState {
        attached_interfaces: attached,
        rules: 0,
    }));

    let listener = bind_control_socket().context("binding control socket")?;
    info!(path = SOCKET_PATH, "control socket listening");

    if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        warn!(error = %e, "sd_notify ready failed (not under systemd?)");
    }

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(e) = serve_client(stream, state).await {
                                warn!(error = %e, "control client error");
                            }
                        });
                    }
                    Err(e) => warn!(error = %e, "control socket accept failed"),
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

async fn serve_client(mut stream: UnixStream, state: Arc<RwLock<DaemonState>>) -> Result<()> {
    let req = read_frame(&mut stream).await?;
    let req: Request = serde_json::from_slice(&req).context("decoding request")?;
    let resp = dispatch(req, &state).await;
    let resp_bytes = serde_json::to_vec(&resp)?;
    write_frame(&mut stream, &resp_bytes).await?;
    Ok(())
}

async fn dispatch(req: Request, state: &Arc<RwLock<DaemonState>>) -> Response {
    match req {
        Request::Ping => Response::Pong,
        Request::Status => {
            let s = state.read().await;
            Response::Status(StatusReport {
                active: true,
                attached_interfaces: s.attached_interfaces.clone(),
                rules: s.rules,
                schema_version: moat_common::SCHEMA_VERSION,
            })
        }
    }
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
