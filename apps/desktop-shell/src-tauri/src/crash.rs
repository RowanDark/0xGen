use std::{
    collections::VecDeque,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use crate::diagnostics::{collect_diagnostics, AnonymizedDiagnostics};
use chrono::{DateTime, Utc};
use flate2::{write::GzEncoder, Compression};
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::Mutex;
use regex::{Captures, Regex};
use reqwest::blocking::Client as BlockingClient;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use thiserror::Error;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt::MakeWriter, EnvFilter};

const LOG_CAPACITY: usize = 10_000;
const PREVIEW_LIMIT: usize = 256 * 1024;
const REDACTION_PLACEHOLDER: &str = "[REDACTED]";

static AUTHORIZATION_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)(authorization\s*[:=]\s*)([^\r\n]+)")
        .expect("invalid authorization regex")
});

static API_KEY_QUOTED_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(api[-_]?key"?\s*[:=]\s*")([^"]+)"#).expect("invalid api key regex")
});

static API_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(api[-_]?key\s*[:=]\s*)([^\s,;]+)").expect("invalid api key regex")
});

static TOKEN_QUOTED_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(token"?\s*[:=]\s*")([^"]+)"#).expect("invalid token regex"));

static TOKEN_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(token\s*[:=]\s*)([^\s,;]+)").expect("invalid token regex"));

static SECRET_QUOTED_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(secret"?\s*[:=]\s*")([^"]+)"#).expect("invalid secret regex"));

static SECRET_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(secret\s*[:=]\s*)([^\s,;]+)").expect("invalid secret regex"));

static PASSWORD_QUOTED_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(password"?\s*[:=]\s*")([^"]+)"#).expect("invalid password regex")
});

static PASSWORD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(password\s*[:=]\s*)([^\s,;]+)").expect("invalid password regex")
});

static BEARER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(bearer\s+)([A-Za-z0-9\-\._~\+/]+=*)").expect("invalid bearer regex")
});

static GLOBAL_REPORTER: OnceCell<CrashReporter> = OnceCell::new();

#[derive(Debug, Error)]
pub enum CrashError {
    #[error("no active crash bundle")]
    NoActiveBundle,
    #[error("invalid crash file path")]
    InvalidPath,
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone)]
pub struct CrashReporter {
    inner: Arc<CrashReporterInner>,
}

struct CrashReporterInner {
    base_url: String,
    log_buffer: LogRingBuffer,
    active: Mutex<Option<CrashBundle>>,
    pending_events: Mutex<Vec<CrashBundleSummary>>,
    app_handle: OnceCell<AppHandle>,
}

struct CrashBundle {
    directory: PathBuf,
    summary: CrashBundleSummary,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashBundleSummary {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub directory: String,
    pub reason: CrashReason,
    pub files: Vec<CrashFileMetadata>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashFileMetadata {
    pub path: String,
    pub bytes: u64,
    pub description: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashReason {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CrashManifest {
    version: String,
    os: String,
    arch: String,
    created_at: DateTime<Utc>,
    base_url: String,
    process_id: u32,
    reason: CrashReason,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CrashMinidump {
    reason: CrashReason,
    captured_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backtrace: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashFilePreview {
    pub path: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Clone)]
pub struct LogRingBuffer {
    inner: Arc<Mutex<VecDeque<String>>>,
    capacity: usize,
}

impl LogRingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    fn push_line(&self, line: &str) {
        let mut guard = self.inner.lock();
        if guard.len() == self.capacity {
            guard.pop_front();
        }
        guard.push_back(line.trim_end_matches('\n').to_string());
    }

    fn snapshot(&self) -> Vec<String> {
        self.inner.lock().iter().cloned().collect()
    }
}

#[derive(Clone)]
struct LogWriterFactory {
    buffer: LogRingBuffer,
}

impl<'a> MakeWriter<'a> for LogWriterFactory {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter {
            buffer: self.buffer.clone(),
            pending: String::new(),
        }
    }
}

struct LogWriter {
    buffer: LogRingBuffer,
    pending: String,
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        self.pending.push_str(&text);

        while let Some(idx) = self.pending.find('\n') {
            let line = self.pending[..idx].to_string();
            self.buffer.push_line(&line);
            println!("{line}");
            self.pending.drain(..=idx);
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let remaining = self.pending.clone();
            self.buffer.push_line(&remaining);
            println!("{remaining}");
            self.pending.clear();
        }
        io::stdout().flush()
    }
}

pub fn init_logging() -> LogRingBuffer {
    static BUFFER: OnceCell<LogRingBuffer> = OnceCell::new();
    static INIT: OnceCell<()> = OnceCell::new();

    let buffer = BUFFER
        .get_or_init(|| LogRingBuffer::new(LOG_CAPACITY))
        .clone();
    INIT.get_or_init(|| {
        let writer = LogWriterFactory {
            buffer: buffer.clone(),
        };

        let env_filter = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new("info"))
            .unwrap_or_else(|_| EnvFilter::new("info"));

        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .json()
            .with_ansi(false)
            .with_writer(writer)
            .try_init();
    });

    buffer
}

pub fn set_global_reporter(reporter: CrashReporter) {
    let _ = GLOBAL_REPORTER.set(reporter);
}

pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        if let Some(reporter) = GLOBAL_REPORTER.get() {
            reporter.capture_rust_panic(info);
        }
    }));
}

impl CrashReporter {
    pub fn new(base_url: String, log_buffer: LogRingBuffer) -> Self {
        Self {
            inner: Arc::new(CrashReporterInner {
                base_url,
                log_buffer,
                active: Mutex::new(None),
                pending_events: Mutex::new(Vec::new()),
                app_handle: OnceCell::new(),
            }),
        }
    }

    pub fn attach_app(&self, app: AppHandle) {
        if self.inner.app_handle.set(app.clone()).is_ok() {
            let mut pending = self.inner.pending_events.lock();
            for summary in pending.drain(..) {
                if let Err(err) = app.emit("crash-bundle-ready", &summary) {
                    error!("failed to emit pending crash bundle event: {err}");
                }
            }
        }
    }

    pub fn log_snapshot(&self) -> Vec<String> {
        self.inner
            .log_buffer
            .snapshot()
            .into_iter()
            .map(|line| redact_text(&line))
            .collect()
    }

    pub fn collect_diagnostics(&self) -> AnonymizedDiagnostics {
        collect_diagnostics(&self.inner.base_url)
    }

    pub fn record_renderer_crash(
        &self,
        message: String,
        stack: Option<String>,
    ) -> Result<CrashBundleSummary, CrashError> {
        let reason = CrashReason {
            kind: "renderer-error".to_string(),
            message,
            stack,
            location: None,
        };
        let summary = self.capture_bundle(reason)?;
        info!(bundle_id = %summary.id, "renderer crash bundle captured");
        Ok(summary)
    }

    pub fn current_bundle(&self) -> Option<CrashBundleSummary> {
        self.inner
            .active
            .lock()
            .as_ref()
            .map(|bundle| bundle.summary.clone())
    }

    pub fn preview_file(&self, relative: &str) -> Result<CrashFilePreview, CrashError> {
        let guard = self.inner.active.lock();
        let bundle = guard.as_ref().ok_or(CrashError::NoActiveBundle)?;
        let full_path = resolve_relative(&bundle.directory, relative)?;
        let metadata = fs::metadata(&full_path)?;

        let mut file = File::open(&full_path)?;
        let mut reader = io::BufReader::new(&mut file);
        let mut content = String::new();
        reader
            .by_ref()
            .take(PREVIEW_LIMIT as u64)
            .read_to_string(&mut content)?;
        let truncated = metadata.len() as usize > PREVIEW_LIMIT;

        Ok(CrashFilePreview {
            path: relative.to_string(),
            content,
            truncated,
        })
    }

    pub fn save_bundle(&self, target: PathBuf) -> Result<(), CrashError> {
        let guard = self.inner.active.lock();
        let bundle = guard.as_ref().ok_or(CrashError::NoActiveBundle)?;
        let file = File::create(target)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all("crash", &bundle.directory)?;
        let encoder = builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

    pub fn discard_bundle(&self) -> Result<(), CrashError> {
        let mut guard = self.inner.active.lock();
        if let Some(bundle) = guard.take() {
            if let Err(err) = fs::remove_dir_all(&bundle.directory) {
                warn!("failed to remove crash directory: {err}");
            }
        }
        Ok(())
    }

    fn capture_bundle(&self, reason: CrashReason) -> Result<CrashBundleSummary, CrashError> {
        let mut guard = self.inner.active.lock();
        if let Some(bundle) = guard.as_ref() {
            return Ok(bundle.summary.clone());
        }

        let created_at = Utc::now();
        let sanitized_reason = sanitize_reason(reason);
        let id = format!(
            "crash-{}",
            created_at
                .format("%Y%m%dT%H%M%S%.3fZ")
                .to_string()
                .replace('.', "")
        );

        let base_dir = std::env::temp_dir().join("0xgen-crashes");
        fs::create_dir_all(&base_dir)?;
        let crash_dir = base_dir.join(&id);
        fs::create_dir_all(&crash_dir)?;

        let mut files = Vec::new();

        // manifest
        let manifest_path = crash_dir.join("manifest.json");
        let manifest = CrashManifest {
            version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            created_at,
            base_url: self.inner.base_url.clone(),
            process_id: std::process::id(),
            reason: sanitized_reason.clone(),
        };
        write_json(&manifest_path, &manifest)?;
        push_file_metadata(
            &mut files,
            "manifest.json",
            &manifest_path,
            "Shell environment manifest",
        )?;

        // logs
        let logs_path = crash_dir.join("logs.ndjson");
        let log_lines = self.log_snapshot();
        if !log_lines.is_empty() {
            let mut file = File::create(&logs_path)?;
            for line in log_lines {
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
            }
            push_file_metadata(
                &mut files,
                "logs.ndjson",
                &logs_path,
                "Structured logs captured from the shell",
            )?;
        }

        // metrics
        if let Some(metrics) = fetch_metrics(&self.inner.base_url) {
            let sanitized_metrics = redact_text(&metrics);
            let metrics_path = crash_dir.join("metrics.prom");
            fs::write(&metrics_path, sanitized_metrics)?;
            push_file_metadata(
                &mut files,
                "metrics.prom",
                &metrics_path,
                "Metrics snapshot compatible with Prometheus",
            )?;
        }

        // diagnostics
        let diagnostics_path = crash_dir.join("diagnostics.json");
        let diagnostics = self.collect_diagnostics();
        write_json(&diagnostics_path, &diagnostics)?;
        push_file_metadata(
            &mut files,
            "diagnostics.json",
            &diagnostics_path,
            "Anonymized system diagnostics",
        )?;

        // minidump
        let minidump_path = crash_dir.join("minidump.json");
        let minidump = CrashMinidump {
            reason: sanitized_reason.clone(),
            captured_at: created_at,
            backtrace: sanitized_reason.stack.clone(),
        };
        write_json(&minidump_path, &minidump)?;
        let minidump_description = match sanitized_reason.kind.as_str() {
            "rust-panic" => "Rust panic backtrace and thread metadata",
            _ => "Renderer stack trace and error metadata",
        };
        push_file_metadata(
            &mut files,
            "minidump.json",
            &minidump_path,
            minidump_description,
        )?;

        let summary = CrashBundleSummary {
            id: id.clone(),
            created_at,
            directory: crash_dir.to_string_lossy().to_string(),
            reason: sanitized_reason,
            files,
        };

        *guard = Some(CrashBundle {
            directory: crash_dir.clone(),
            summary: summary.clone(),
        });

        self.emit_summary(&summary);

        Ok(summary)
    }

    fn emit_summary(&self, summary: &CrashBundleSummary) {
        if let Some(app) = self.inner.app_handle.get() {
            if let Err(err) = app.emit("crash-bundle-ready", summary) {
                error!("failed to emit crash bundle event: {err}");
            }
        } else {
            self.inner.pending_events.lock().push(summary.clone());
        }
    }

    pub fn capture_rust_panic(&self, info: &std::panic::PanicInfo) {
        let message = match info.payload().downcast_ref::<&str>() {
            Some(s) => s.to_string(),
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => s.clone(),
                None => "unknown panic".to_string(),
            },
        };

        let location = info
            .location()
            .map(|loc| format!("{}:{}", loc.file(), loc.line()));

        let backtrace = std::backtrace::Backtrace::force_capture().to_string();

        let reason = CrashReason {
            kind: "rust-panic".to_string(),
            message,
            stack: Some(backtrace.clone()),
            location,
        };

        match self.capture_bundle(reason.clone()) {
            Ok(summary) => {
                info!(bundle_id = %summary.id, "captured crash bundle for rust panic");
            }
            Err(err) => {
                error!("failed to capture panic bundle: {err}");
            }
        }
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), io::Error> {
    let json = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string());
    fs::write(path, json)
}

fn push_file_metadata(
    files: &mut Vec<CrashFileMetadata>,
    relative: &str,
    path: &Path,
    description: &str,
) -> Result<(), io::Error> {
    let metadata = fs::metadata(path)?;
    files.push(CrashFileMetadata {
        path: relative.to_string(),
        bytes: metadata.len(),
        description: description.to_string(),
    });
    Ok(())
}

fn resolve_relative(root: &Path, relative: &str) -> Result<PathBuf, CrashError> {
    let candidate = Path::new(relative);
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(CrashError::InvalidPath);
    }
    let full = root.join(candidate);
    if !full.starts_with(root) {
        return Err(CrashError::InvalidPath);
    }
    Ok(full)
}

fn fetch_metrics(base_url: &str) -> Option<String> {
    static CLIENT: Lazy<BlockingClient> = Lazy::new(|| {
        BlockingClient::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build blocking client")
    });

    let endpoint = format!("{}/metrics", base_url.trim_end_matches('/'));

    match CLIENT.get(endpoint).send() {
        Ok(response) => match response.error_for_status() {
            Ok(success) => success.text().ok(),
            Err(err) => {
                warn!("failed to fetch metrics: {err}");
                None
            }
        },
        Err(err) => {
            warn!("failed to contact metrics endpoint: {err}");
            None
        }
    }
}

pub fn record_renderer_crash(message: String, stack: Option<String>) {
    if let Some(reporter) = GLOBAL_REPORTER.get() {
        if let Err(err) = reporter.record_renderer_crash(message, stack) {
            error!("failed to record renderer crash: {err}");
        }
    }
}

pub(crate) fn redact_text(input: &str) -> String {
    let mut text = input.to_string();

    text = AUTHORIZATION_PATTERN
        .replace_all(&text, |caps: &Captures| {
            format!("{}{}", &caps[1], REDACTION_PLACEHOLDER)
        })
        .into_owned();

    for pattern in [
        &*API_KEY_QUOTED_PATTERN,
        &*TOKEN_QUOTED_PATTERN,
        &*SECRET_QUOTED_PATTERN,
        &*PASSWORD_QUOTED_PATTERN,
    ] {
        text = pattern
            .replace_all(&text, |caps: &Captures| {
                format!("{}{}\"", &caps[1], REDACTION_PLACEHOLDER)
            })
            .into_owned();
    }

    for pattern in [
        &*API_KEY_PATTERN,
        &*TOKEN_PATTERN,
        &*SECRET_PATTERN,
        &*PASSWORD_PATTERN,
    ] {
        text = pattern
            .replace_all(&text, |caps: &Captures| {
                format!("{}{}", &caps[1], REDACTION_PLACEHOLDER)
            })
            .into_owned();
    }

    text = BEARER_PATTERN
        .replace_all(&text, |caps: &Captures| {
            format!("{}{}", &caps[1], REDACTION_PLACEHOLDER)
        })
        .into_owned();

    text
}

fn sanitize_reason(mut reason: CrashReason) -> CrashReason {
    reason.message = redact_text(&reason.message);
    reason.stack = reason.stack.map(|stack| redact_text(&stack));
    reason.location = reason.location.map(|location| redact_text(&location));
    reason
}

pub fn current_summary() -> Option<CrashBundleSummary> {
    GLOBAL_REPORTER
        .get()
        .and_then(|reporter| reporter.current_bundle())
}

pub fn preview(relative: &str) -> Result<CrashFilePreview, CrashError> {
    GLOBAL_REPORTER
        .get()
        .ok_or(CrashError::NoActiveBundle)?
        .preview_file(relative)
}

pub fn save(target: PathBuf) -> Result<(), CrashError> {
    GLOBAL_REPORTER
        .get()
        .ok_or(CrashError::NoActiveBundle)?
        .save_bundle(target)
}

pub fn discard() -> Result<(), CrashError> {
    GLOBAL_REPORTER
        .get()
        .ok_or(CrashError::NoActiveBundle)?
        .discard_bundle()
}
