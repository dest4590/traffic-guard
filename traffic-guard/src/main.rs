use std::time::Duration;

use anyhow::Context;
use aya::{
    maps::Array,
    programs::{tc, SchedClassifier, TcAttachType},
};
use clap::{Parser, ValueEnum};
use log::{debug, error, info, warn};
use tokio::signal;
use traffic_guard_common::{GuardConfig, GuardState};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Direction {
    Ingress,
    Egress,
    Both,
}

#[derive(Debug, Parser)]
#[command(
    name = "traffic-guard",
    about = "eBPF/TC traffic limiter and token bucket rate limiter"
)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(long, default_value_t = 85)]
    limit_gb: u64,

    #[clap(long, default_value_t = 75)]
    release_gb: u64,

    #[clap(long, default_value_t = 9)]
    rate_mbps: u64,

    #[clap(long, default_value_t = 60)]
    window_mins: u64,

    #[clap(long, value_enum, default_value_t = Direction::Both)]
    direction: Direction,

    #[clap(long, default_value_t = 5)]
    poll_secs: u64,

    #[clap(long)]
    status_file: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/traffic-guard"
    )))
    .context("failed to load eBPF bytecode")?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger (expected if logs are stripped): {e}");
    }

    let throttle_rate_bps = (opt.rate_mbps * 1_000_000) / 8;
    let cfg = GuardConfig {
        limit_bytes: opt.limit_gb * 1024 * 1024 * 1024,
        release_bytes: opt.release_gb * 1024 * 1024 * 1024,
        window_duration_ns: opt.window_mins * 60 * 1_000_000_000,
        throttle_rate_bps,
        token_burst_bytes: 64 * 1024,
    };

    {
        let mut config_map: Array<_, GuardConfig> =
            Array::try_from(ebpf.map_mut("CONFIG").context("missing CONFIG map")?)?;
        config_map.set(0, cfg, 0)?;
        info!(
            "configured limit: {} GB, release: {} GB, window: {} min, throttle: {} Mbps",
            opt.limit_gb, opt.release_gb, opt.window_mins, opt.rate_mbps
        );
    }

    let _ = tc::qdisc_add_clsact(&opt.iface);

    let program: &mut SchedClassifier = ebpf
        .program_mut("traffic_guard")
        .context("missing traffic_guard program")?
        .try_into()?;
    program.load().context("failed to load classifier")?;

    match opt.direction {
        Direction::Ingress => {
            program
                .attach(&opt.iface, TcAttachType::Ingress)
                .context("failed to attach to ingress")?;
            info!("attached classifier to {} (ingress)", opt.iface);
        }
        Direction::Egress => {
            program
                .attach(&opt.iface, TcAttachType::Egress)
                .context("failed to attach to egress")?;
            info!("attached classifier to {} (egress)", opt.iface);
        }
        Direction::Both => {
            program
                .attach(&opt.iface, TcAttachType::Ingress)
                .context("failed to attach to ingress")?;
            program
                .attach(&opt.iface, TcAttachType::Egress)
                .context("failed to attach to egress")?;
            info!("attached classifier to {} (ingress + egress)", opt.iface);
        }
    }

    let state_map: Array<_, GuardState> =
        Array::try_from(ebpf.map("STATE").context("missing STATE map")?)?;

    info!("traffic-guard running. press Ctrl+C to stop.");

    let poll_interval = Duration::from_secs(opt.poll_secs.max(1));
    let mut interval = tokio::time::interval(poll_interval);

    let shutdown_signal = async {
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = sigint.recv() => Ok::<_, anyhow::Error>(()),
            _ = sigterm.recv() => Ok(()),
            _ = signal::ctrl_c() => Ok(()),
        }
    };
    tokio::pin!(shutdown_signal);

    loop {
        tokio::select! {
            _ = &mut shutdown_signal => {
                info!("received termination signal, shutting down...");
                break;
            }
            _ = interval.tick() => {
                match state_map.get(&0, 0) {
                    Ok(state) => {
                        let used_gb = state.bytes_window as f64 / (1024.0 * 1024.0 * 1024.0);
                        let limit_gb = opt.limit_gb as f64;
                        let pct = if limit_gb > 0.0 { (used_gb / limit_gb) * 100.0 } else { 0.0 };
                        let status_str = if state.is_throttled != 0 {
                            format!("THROTTLED (capped to {} Mbps)", opt.rate_mbps)
                        } else {
                            "NORMAL (full speed)".to_string()
                        };

                        info!(
                            "window usage: {:.2} / {:.0} GB ({:.1}%) | status: {}",
                            used_gb, limit_gb, pct, status_str
                        );

                        if let Some(ref path) = opt.status_file {
                            let content = format!(
                                "traffic-guard: {:.2}/{:.0} GB ({:.1}%) [1h] | {}\n",
                                used_gb, limit_gb, pct, status_str
                            );
                            let _ = std::fs::write(path, content);
                        }
                    }
                    Err(e) => {
                        error!("failed to read state map: {e}");
                    }
                }
            }
        }
    }

    info!("cleaning up tc qdisc...");
    if let Some(ref path) = opt.status_file {
        let _ = std::fs::remove_file(path);
    }
    let _ = tc::qdisc_detach_program(&opt.iface, TcAttachType::Ingress, "traffic_guard");
    let _ = tc::qdisc_detach_program(&opt.iface, TcAttachType::Egress, "traffic_guard");
    info!("traffic-guard stopped cleanly.");

    Ok(())
}
