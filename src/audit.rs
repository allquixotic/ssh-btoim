//! Append-only JSONL audit trail of every tool call.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::warn;

const MAX_COMMAND_BYTES: usize = 4096;

#[derive(Debug, Serialize)]
pub struct AuditEvent<'a> {
    pub ts: String,
    pub tool: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<usize>,
    /// ok | error | denied | timeout
    pub outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<'a> AuditEvent<'a> {
    pub fn new(tool: &'a str, outcome: &'a str) -> Self {
        AuditEvent {
            ts: now_rfc3339(),
            tool,
            host: None,
            user: None,
            hostname: None,
            command: None,
            remote_path: None,
            exit_code: None,
            duration_ms: None,
            bytes: None,
            outcome,
            error: None,
        }
    }

    pub fn command(mut self, cmd: &str) -> Self {
        let mut c = cmd.to_string();
        if c.len() > MAX_COMMAND_BYTES {
            let mut cut = MAX_COMMAND_BYTES;
            while !c.is_char_boundary(cut) {
                cut -= 1;
            }
            c.truncate(cut);
            c.push_str("…[truncated]");
        }
        self.command = Some(c);
        self
    }
}

pub struct Audit {
    file: Mutex<fs::File>,
}

impl Audit {
    pub fn open(path: &Path) -> Result<Audit> {
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("cannot open audit log {}", path.display()))?;
        Ok(Audit {
            file: Mutex::new(file),
        })
    }

    pub fn record(&self, ev: &AuditEvent<'_>) {
        let line = match serde_json::to_string(ev) {
            Ok(l) => l,
            Err(e) => {
                warn!("cannot serialize audit event: {e}");
                return;
            }
        };
        let mut f = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = writeln!(f, "{line}") {
            warn!("cannot write audit log: {e}");
        }
    }
}

pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn writes_jsonl_with_private_mode() {
        let dir =
            std::env::temp_dir().join(format!("ssh-btoim-audit-{}", crate::output::random_id()));
        let path = dir.join("sub").join("audit.jsonl");
        let a = Audit::open(&path).unwrap();
        let ev = AuditEvent::new("ssh_exec", "ok").command(&"x".repeat(5000));
        a.record(&ev);
        let text = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v["tool"], "ssh_exec");
        assert!(v["command"].as_str().unwrap().ends_with("[truncated]"));
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
    }
}
