#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
use traffic_guard_common::{GuardConfig, GuardState};

#[map]
static CONFIG: Array<GuardConfig> = Array::with_max_entries(1, 0);

#[map]
static STATE: Array<GuardState> = Array::with_max_entries(1, 0);

#[classifier]
pub fn traffic_guard(ctx: TcContext) -> i32 {
    match try_traffic_guard(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn try_traffic_guard(ctx: TcContext) -> Result<i32, i32> {
    let cfg_ptr = CONFIG.get_ptr(0).ok_or(TC_ACT_PIPE)?;
    let state_ptr = STATE.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;

    let cfg = unsafe { &*cfg_ptr };
    let state = unsafe { &mut *state_ptr };

    let pkt_len = ctx.len() as u64;
    let now = unsafe { bpf_ktime_get_ns() };

    if state.window_start_ns == 0 {
        state.window_start_ns = now;
        state.last_refill_ns = now;
        state.tokens = cfg.token_burst_bytes;
        state.bytes_window = 0;
        state.is_throttled = 0;
    } else if cfg.window_duration_ns > 0
        && now >= state.window_start_ns
        && (now - state.window_start_ns) >= cfg.window_duration_ns
    {
        state.window_start_ns = now;
        state.bytes_window = 0;
        state.is_throttled = 0;
        state.last_refill_ns = now;
        state.tokens = cfg.token_burst_bytes;
    }

    state.bytes_window = state.bytes_window.saturating_add(pkt_len);

    if state.is_throttled == 0 {
        if state.bytes_window >= cfg.limit_bytes {
            state.is_throttled = 1;
            state.last_refill_ns = now;
            state.tokens = cfg.token_burst_bytes;
        }
    } else if state.bytes_window <= cfg.release_bytes {
        state.is_throttled = 0;
    }

    if state.is_throttled == 0 {
        return Ok(TC_ACT_PIPE);
    }

    if now > state.last_refill_ns {
        let elapsed_ns = now - state.last_refill_ns;
        let elapsed_ms = elapsed_ns / 1_000_000;

        if elapsed_ms > 0 {
            let rate_bpms = cfg.throttle_rate_bps / 1000;
            let new_tokens = elapsed_ms * rate_bpms;
            state.tokens = if state.tokens + new_tokens > cfg.token_burst_bytes {
                cfg.token_burst_bytes
            } else {
                state.tokens + new_tokens
            };
            state.last_refill_ns = now;
        }
    }

    if state.tokens >= pkt_len {
        state.tokens -= pkt_len;
        Ok(TC_ACT_PIPE)
    } else {
        Ok(TC_ACT_SHOT)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"MIT\0";
