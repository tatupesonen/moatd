//! Microbenchmark + decision oracle for the moat eBPF programs via
//! `BPF_PROG_TEST_RUN`. Hermetic: no netns and no traffic. It loads the program,
//! populates the maps for a scenario, feeds a crafted packet, and reports the
//! verdict and average ns/run. Run as root: `sudo ./target/debug/bpf-bench`.

use std::os::fd::{AsFd, AsRawFd};

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap},
    programs::{SchedClassifier, Xdp},
    Ebpf,
};
use moatd_common::{
    ConnKey, ConnVal, GlobalConfig, IpCidr, Rule, ACT_ALLOW, ACT_DENY, DIR_IN, FAMILY_V4,
    IFACE_ANY, POLICY_IN, POLICY_OUT, PROTO_TCP, RULES_MAX, SCHEMA_VERSION,
};

const BPF_PROG_TEST_RUN: i64 = 10;
const REPEAT: u32 = 1_000_000;

// XDP / TC return codes.
const XDP_ABORTED: u32 = 0;
const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;
const TC_ACT_SHOT: u32 = 2;
const TC_ACT_PIPE: u32 = 3;

#[repr(C)]
#[derive(Default)]
struct TestRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
}

fn test_run(prog_fd: i32, data: &[u8]) -> Result<(u32, u32)> {
    let mut out = vec![0u8; 2048];
    loop {
        // zeroed(), not field-init: the kernel's CHECK_ATTR rejects any
        // non-zero trailing bytes, including this struct's padding.
        let mut attr: TestRunAttr = unsafe { std::mem::zeroed() };
        attr.prog_fd = prog_fd as u32;
        attr.data_size_in = data.len() as u32;
        attr.data_size_out = out.len() as u32;
        attr.data_in = data.as_ptr() as u64;
        attr.data_out = out.as_mut_ptr() as u64;
        attr.repeat = REPEAT;
        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_TEST_RUN,
                std::ptr::addr_of_mut!(attr).cast::<libc::c_void>(),
                std::mem::size_of::<TestRunAttr>(),
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue; // kernel rescheduled mid-batch; retry
            }
            return Err(anyhow!("BPF_PROG_TEST_RUN: {err}"));
        }
        return Ok((attr.retval, attr.duration));
    }
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn ip(a: u8, b: u8, c: u8, d: u8) -> [u8; 4] {
    [a, b, c, d]
}

/// Ethernet + IPv4 + TCP SYN. No checksums (XDP doesn't validate them).
fn v4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 20 + 20];
    p[12] = 0x08; // ethertype 0x0800
    p[14] = 0x45; // v4, ihl=5
    p[16..18].copy_from_slice(&40u16.to_be_bytes()); // total len
    p[22] = 64; // ttl
    p[23] = 6; // proto tcp
    p[26..30].copy_from_slice(&src);
    p[30..34].copy_from_slice(&dst);
    p[34..36].copy_from_slice(&sport.to_be_bytes());
    p[36..38].copy_from_slice(&dport.to_be_bytes());
    p[46] = 0x50; // data offset 5
    p[47] = 0x02; // SYN
    p
}

/// A rule that matches proto+port (so the cheap checks pass) but has a src CIDR
/// the packet misses, forcing `cidr_contains` to run on every slot.
fn rule_v4_cidr_miss(dport: u16) -> Rule {
    let mut src = IpCidr::any_v4();
    src.prefix = 24;
    src.addr[..4].copy_from_slice(&[192, 168, 0, 0]);
    let mut r = rule_v4_dport(DIR_IN, ACT_ALLOW, dport);
    r.src = src;
    r
}

fn rule_v4_dport(direction: u8, action: u8, dport: u16) -> Rule {
    Rule {
        version: SCHEMA_VERSION,
        direction,
        action,
        proto: PROTO_TCP,
        iface_ifindex: IFACE_ANY,
        src: IpCidr::any_v4(),
        dst: IpCidr::any_v4(),
        src_port_min: 0,
        src_port_max: 0,
        dst_port_min: dport,
        dst_port_max: dport,
        enabled: 1,
        _pad: [0; 3],
    }
}

struct Maps<'a> {
    ebpf: &'a mut Ebpf,
}

impl Maps<'_> {
    fn config(&mut self, active_bank: u8, rule_count: u16) -> Result<()> {
        let mut m: Array<_, GlobalConfig> =
            Array::try_from(self.ebpf.map_mut("CONFIG").context("CONFIG")?)?;
        let cfg = GlobalConfig {
            logging_enabled: 0,
            log_level: 0,
            active_bank,
            conntrack_enabled: 1,
            rule_count,
            _pad2: 0,
        };
        m.set(0, cfg, 0)?;
        Ok(())
    }

    fn defaults(&mut self, policy_in: u8, policy_out: u8) -> Result<()> {
        let mut m: Array<_, u8> =
            Array::try_from(self.ebpf.map_mut("DEFAULT_POLICY").context("DEFAULT_POLICY")?)?;
        m.set(POLICY_IN, policy_in, 0)?;
        m.set(POLICY_OUT, policy_out, 0)?;
        Ok(())
    }

    fn rules(&mut self, bank: u8, rules: &[Rule]) -> Result<()> {
        let mut m: Array<_, Rule> = Array::try_from(self.ebpf.map_mut("RULES").context("RULES")?)?;
        let base = u32::from(bank) * RULES_MAX;
        for (i, r) in rules.iter().enumerate() {
            m.set(base + i as u32, *r, 0)?;
        }
        Ok(())
    }

    fn insert_conn(&mut self, key: ConnKey) -> Result<()> {
        let mut m: HashMap<_, ConnKey, ConnVal> =
            HashMap::try_from(self.ebpf.map_mut("CONNTRACK").context("CONNTRACK")?)?;
        m.insert(key, ConnVal { last_seen_ns: monotonic_ns() }, 0)?;
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.config(0, 0)?;
        self.defaults(ACT_ALLOW, ACT_ALLOW)?;
        Ok(())
    }
}

fn verdict_name(code: u32, tc: bool) -> &'static str {
    if tc {
        match code {
            TC_ACT_SHOT => "SHOT(drop)",
            TC_ACT_PIPE => "PIPE(pass)",
            _ => "?",
        }
    } else {
        match code {
            XDP_PASS => "PASS",
            XDP_DROP => "DROP",
            XDP_ABORTED => "ABORTED",
            _ => "?",
        }
    }
}

fn main() -> Result<()> {
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/moatd-bpf")))
        .context("loading eBPF object")?;

    let xdp_fd = {
        let prog: &mut Xdp =
            ebpf.program_mut("moat_ingress").context("moat_ingress")?.try_into()?;
        prog.load()?;
        prog.fd()?.as_fd().as_raw_fd()
    };
    let tc_fd = {
        let prog: &mut SchedClassifier =
            ebpf.program_mut("moat_egress").context("moat_egress")?.try_into()?;
        prog.load()?;
        prog.fd()?.as_fd().as_raw_fd()
    };

    let host = ip(10, 0, 0, 1);
    let peer = ip(10, 0, 0, 2);
    let pkt_in = v4_tcp(peer, host, 40000, 80); // peer -> host:80
    let pkt_out = v4_tcp(host, peer, 40000, 80); // host -> peer:80

    let mut maps = Maps { ebpf: &mut ebpf };

    println!("{:<48} {:>10} {:>10}", "scenario", "verdict", "ns/pkt");
    println!("{}", "-".repeat(70));

    let row = |name: &str, fd: i32, pkt: &[u8], tc: bool| -> Result<()> {
        let (ret, dur) = test_run(fd, pkt)?;
        println!("{name:<48} {:>10} {dur:>10}", verdict_name(ret, tc));
        Ok(())
    };

    // --- ingress (XDP) ---
    maps.reset()?;
    row("ingress: default-allow, 0 rules (new flow)", xdp_fd, &pkt_in, false)?;

    maps.reset()?;
    maps.defaults(ACT_DENY, ACT_ALLOW)?;
    row("ingress: default-deny, 0 rules (DROP)", xdp_fd, &pkt_in, false)?;

    // Established: pre-insert the reverse-direction conntrack entry the ingress
    // fast-path looks up (src/dst and ports swapped relative to the packet).
    maps.reset()?;
    maps.defaults(ACT_DENY, ACT_ALLOW)?;
    maps.insert_conn(ConnKey {
        proto: PROTO_TCP,
        family: FAMILY_V4,
        _pad: [0; 2],
        src_addr: pad16(host),
        dst_addr: pad16(peer),
        src_port: 80,
        dst_port: 40000,
    })?;
    row("ingress: established (conntrack hit)", xdp_fd, &pkt_in, false)?;

    // 256 non-matching rules, default allow: the worst-case full rule walk.
    maps.reset()?;
    let many: Vec<Rule> =
        (0..RULES_MAX).map(|i| rule_v4_dport(DIR_IN, ACT_ALLOW, 1000 + i as u16)).collect();
    maps.rules(0, &many)?;
    maps.config(0, RULES_MAX as u16)?;
    row("ingress: 256 rules, no match (new flow)", xdp_fd, &pkt_in, false)?;

    // Worst case: 256 rules that pass proto+port but miss on src CIDR, so
    // cidr_contains runs on every slot.
    maps.reset()?;
    let walk: Vec<Rule> = (0..RULES_MAX).map(|_| rule_v4_cidr_miss(80)).collect();
    maps.rules(0, &walk)?;
    maps.config(0, RULES_MAX as u16)?;
    row("ingress: 256 rules, cidr-miss (worst-case walk)", xdp_fd, &pkt_in, false)?;

    // Verify the walk really traverses all 256: default-deny, 255 non-matching
    // rules, and the only allow at slot 255. PASS proves we reached it.
    maps.reset()?;
    maps.defaults(ACT_DENY, ACT_ALLOW)?;
    let mut deep: Vec<Rule> = (0..255).map(|_| rule_v4_cidr_miss(80)).collect();
    deep.push(rule_v4_dport(DIR_IN, ACT_ALLOW, 80));
    maps.rules(0, &deep)?;
    maps.config(0, RULES_MAX as u16)?;
    row("ingress: match at slot 255 (proves full walk)", xdp_fd, &pkt_in, false)?;

    // Match at slot 0.
    maps.reset()?;
    maps.rules(0, &[rule_v4_dport(DIR_IN, ACT_ALLOW, 80)])?;
    maps.config(0, 1)?;
    row("ingress: rule match at slot 0", xdp_fd, &pkt_in, false)?;

    // --- egress (TC) ---
    maps.reset()?;
    row("egress: default-allow, 0 rules (new flow)", tc_fd, &pkt_out, true)?;

    maps.reset()?;
    maps.insert_conn(ConnKey {
        proto: PROTO_TCP,
        family: FAMILY_V4,
        _pad: [0; 2],
        src_addr: pad16(host),
        dst_addr: pad16(peer),
        src_port: 40000,
        dst_port: 80,
    })?;
    row("egress: established (conntrack hit)", tc_fd, &pkt_out, true)?;

    maps.reset()?;
    maps.rules(0, &many)?;
    maps.config(0, RULES_MAX as u16)?;
    row("egress: 256 rules, no match (new flow)", tc_fd, &pkt_out, true)?;

    Ok(())
}

fn pad16(v: [u8; 4]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&v);
    a
}
