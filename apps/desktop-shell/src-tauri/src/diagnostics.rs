use chrono::{DateTime, Local, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
use url::Url;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnonymizedDiagnostics {
    pub captured_at: DateTime<Utc>,
    pub version: String,
    pub os: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    pub architecture: String,
    pub uptime_seconds: u64,
    pub logical_cpus: usize,
    pub physical_cpus: Option<usize>,
    pub total_memory_bytes: u64,
    pub available_memory_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_hash: Option<String>,
    pub timezone_offset_minutes: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_hostname: Option<String>,
}

pub fn collect_diagnostics(api_base_url: &str) -> AnonymizedDiagnostics {
    let mut system = System::new_with_specifics(
        RefreshKind::new()
            .with_cpu(CpuRefreshKind::new())
            .with_memory(MemoryRefreshKind::everything()),
    );
    system.refresh_cpu();
    system.refresh_memory();

    let hostname_hash = System::host_name().and_then(|hostname| {
        if hostname.trim().is_empty() {
            None
        } else {
            Some(hash_identifier(&hostname))
        }
    });

    let captured_at = Utc::now();
    let timezone_offset_minutes = Local::now().offset().local_minus_utc() / 60;

    let total_memory_bytes = system.total_memory() * 1024;
    let available_memory_bytes = system.available_memory() * 1024;

    let api_hostname = Url::parse(api_base_url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_string()));

    AnonymizedDiagnostics {
        captured_at,
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        os_version: System::long_os_version(),
        kernel_version: System::kernel_version(),
        architecture: std::env::consts::ARCH.to_string(),
        uptime_seconds: System::uptime(),
        logical_cpus: system.cpus().len(),
        physical_cpus: system.physical_core_count(),
        total_memory_bytes,
        available_memory_bytes,
        hostname_hash,
        timezone_offset_minutes,
        api_hostname,
    }
}

fn hash_identifier(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let hash = hasher.finalize();
    let mut short = String::with_capacity(24);
    for byte in hash.iter().take(12) {
        let _ = write!(&mut short, "{:02x}", byte);
    }
    short
}
