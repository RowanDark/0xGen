use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use flate2::{write::GzEncoder, Compression};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tar::Builder;
use thiserror::Error;

use crate::crash::{self, CrashReporter};

#[derive(Debug, Error)]
pub enum FeedbackError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedbackSubmission {
    pub bundle_path: String,
    pub included_logs: bool,
    pub included_crash: bool,
    pub included_diagnostics: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FeedbackManifest {
    id: String,
    created_at: DateTime<Utc>,
    category: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_hash: Option<String>,
    include_logs: bool,
    include_crash: bool,
    include_diagnostics: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    crash_bundle: Option<CrashBundleInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CrashBundleInfo {
    id: String,
    created_at: DateTime<Utc>,
    file_count: usize,
    reason: crash::CrashReason,
}

pub fn create_feedback_bundle(
    reporter: &CrashReporter,
    category: String,
    message: String,
    contact: Option<String>,
    include_logs: bool,
    include_crash: bool,
    include_diagnostics: bool,
) -> Result<FeedbackSubmission, FeedbackError> {
    let created_at = Utc::now();
    let id = format!(
        "feedback-{}",
        created_at
            .format("%Y%m%dT%H%M%S%.3fZ")
            .to_string()
            .replace('.', "")
    );

    let base_dir = std::env::temp_dir().join("0xgen-feedback");
    fs::create_dir_all(&base_dir)?;
    let feedback_dir = base_dir.join(&id);
    fs::create_dir_all(&feedback_dir)?;

    let sanitized_message = crash::redact_text(message.trim());
    let masked_contact = contact.as_ref().map(|value| mask_contact(value));
    let contact_hash = contact.as_ref().map(|value| short_hash(value));

    let active_bundle = if include_crash {
        reporter.current_bundle()
    } else {
        None
    };
    let crash_directory = active_bundle
        .as_ref()
        .map(|summary| PathBuf::from(&summary.directory));
    let crash_summary = active_bundle.as_ref().map(|summary| CrashBundleInfo {
        id: summary.id.clone(),
        created_at: summary.created_at,
        file_count: summary.files.len(),
        reason: summary.reason.clone(),
    });

    let mut logs_written = false;
    if include_logs {
        let logs = reporter.log_snapshot();
        if !logs.is_empty() {
            let logs_path = feedback_dir.join("logs.ndjson");
            let mut file = File::create(&logs_path)?;
            for line in logs {
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
            }
            logs_written = true;
        }
    }

    let mut wrote_diagnostics = false;
    if include_diagnostics {
        let diagnostics = reporter.collect_diagnostics();
        let path = feedback_dir.join("diagnostics.json");
        write_json(&path, &diagnostics)?;
        wrote_diagnostics = true;
    }

    let mut crash_written = false;
    if let Some(crash_path) = crash_directory.as_ref() {
        if include_crash && crash_path.exists() {
            let target = feedback_dir.join("crash");
            copy_dir_recursive(crash_path, &target)?;
            crash_written = true;
        }
    }

    let manifest = FeedbackManifest {
        id: id.clone(),
        created_at,
        category,
        message: sanitized_message,
        contact: masked_contact,
        contact_hash,
        include_logs: logs_written,
        include_crash: crash_written,
        include_diagnostics: wrote_diagnostics,
        crash_bundle: if crash_written { crash_summary } else { None },
    };

    let manifest_path = feedback_dir.join("feedback.json");
    write_json(&manifest_path, &manifest)?;

    let archive_path = base_dir.join(format!("{id}.tar.gz"));
    let file = File::create(&archive_path)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);
    builder.append_dir_all("feedback", &feedback_dir)?;
    let encoder = builder.into_inner()?;
    encoder.finish()?;

    fs::remove_dir_all(&feedback_dir)?;

    Ok(FeedbackSubmission {
        bundle_path: archive_path.to_string_lossy().to_string(),
        included_logs: logs_written,
        included_crash: crash_written,
        included_diagnostics: include_diagnostics && wrote_diagnostics,
    })
}

fn mask_contact(contact: &str) -> String {
    if let Some(at_pos) = contact.find('@') {
        let (user, domain) = contact.split_at(at_pos);
        let masked_user = mask_fragment(user);
        format!("{}{}", masked_user, domain)
    } else {
        mask_fragment(contact)
    }
}

fn mask_fragment(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= 2 {
        return "*".repeat(chars.len());
    }
    for ch in chars.iter_mut().skip(1).take(chars.len() - 2) {
        *ch = '*';
    }
    chars.into_iter().collect()
}

fn short_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.trim().as_bytes());
    let hash = hasher.finalize();
    hash.iter()
        .take(12)
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), FeedbackError> {
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json)?;
    Ok(())
}

fn copy_dir_recursive(source: &Path, target: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}
