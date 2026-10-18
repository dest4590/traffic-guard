# traffic-guard

eBPF traffic guard and token bucket rate limiter built with Aya (Rust).

Designed for VPS hosts with strict hourly bandwidth quotas (e.g. 100 GB/hour with aggressive throttling when exceeded).

Instead of waiting for the hosting provider to throttle your entire server, `traffic-guard` runs directly in the Linux kernel via a `tc` (`clsact`) classifier on both ingress and egress:
- Tracks total bytes transferred in a sliding 1-hour window.
- When usage hits the configured limit (default: 85 GB), it activates a token bucket filter inside eBPF.
- Clamps throughput to a safe rate (default: 9 Mbps) to keep you under the quota.
- Automatically resets the counter and restores full line rate once the window rolls over.

## Architecture

- `traffic-guard-common`: shared C-compatible structs (`GuardState`, `GuardConfig`) between kernel and userspace.
- `traffic-guard-ebpf`: the eBPF classifier program. Runs inside kernel TC, handles packet accounting and token bucket drops without userspace round-trips.
- `traffic-guard`: userspace daemon. Loads eBPF bytecode, configures limits, monitors live stats, and handles cleanup on shutdown.

## Requirements

- Linux kernel >= 5.15 with BTF support (`/sys/kernel/btf/vmlinux`)
- Stable Rust toolchain
- Nightly toolchain with source: `rustup toolchain install nightly --component rust-src`
- `bpf-linker`: `cargo install bpf-linker`

## Building

Native build:
```bash
cargo build --release
```

Cross-compiling for `x86_64` musl (e.g. from an ARM64 host):
```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The resulting binary in `target/.../release/traffic-guard` is completely static and bundles the eBPF bytecode.

## Usage

Run directly:
```bash
sudo ./traffic-guard -i eth0 --limit-gb 85 --release-gb 75 --rate-mbps 9 --window-mins 60 --direction both
```

CLI options:
- `-i, --iface`: network interface to attach to (default: `eth0`)
- `--limit-gb`: quota limit in GB before throttling kicks in (default: `85`)
- `--release-gb`: usage threshold in GB to release throttling (default: `75`)
- `--rate-mbps`: capped speed in Mbps while throttled (default: `9`)
- `--window-mins`: window duration in minutes (default: `60`)
- `--direction`: traffic to monitor: `both`, `ingress`, or `egress` (default: `both`)
- `--poll-secs`: stats logging interval in seconds (default: `5`)
- `--status-file`: optional path to dump a single-line status file (useful for shell prompts/motd)

## Systemd Service

```ini
[Unit]
Description=Traffic Guard eBPF Rate Limiter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/traffic-guard -i eth0 --limit-gb 85 --release-gb 75 --rate-mbps 9 --window-mins 60 --direction both --poll-secs 10 --status-file /var/run/traffic-guard.status
Restart=always
RestartSec=5
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo cp target/release/traffic-guard /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now traffic-guard
```

## License

MIT
