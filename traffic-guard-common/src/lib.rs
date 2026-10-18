#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GuardState {
    pub window_start_ns: u64,
    pub bytes_window: u64,
    pub is_throttled: u32,
    pub _pad: u32,
    pub last_refill_ns: u64,
    pub tokens: u64,
}

impl Default for GuardState {
    fn default() -> Self {
        Self {
            window_start_ns: 0,
            bytes_window: 0,
            is_throttled: 0,
            _pad: 0,
            last_refill_ns: 0,
            tokens: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GuardConfig {
    pub limit_bytes: u64,
    pub release_bytes: u64,
    pub window_duration_ns: u64,
    pub throttle_rate_bps: u64,
    pub token_burst_bytes: u64,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            limit_bytes: 85 * 1024 * 1024 * 1024,
            release_bytes: 75 * 1024 * 1024 * 1024,
            window_duration_ns: 3600 * 1_000_000_000,
            throttle_rate_bps: 1_125_000,
            token_burst_bytes: 64 * 1024,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GuardState {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GuardConfig {}
