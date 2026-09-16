//! Command output formatting and large-output spill files.
//!
//! Output above the inline limit is written to a per-process directory
//! (mode 0700, files 0600) and the response carries a head/tail preview plus
//! the path. Directories left behind by crashed instances are removed at
//! startup when their owning PID is gone.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{info, warn};

const PREVIEW_BYTES: usize = 2 * 1024;
const DIR_PREFIX: &str = "ssh-btoim-";

pub struct OutputHandler {
    pub dir: PathBuf,
}

#[derive(Debug, Default, Clone)]
pub struct ExecOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub duration: Duration,
    pub timed_out: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl OutputHandler {
    pub fn new(base_override: Option<&Path>) -> Result<OutputHandler> {
        let base = match base_override {
            Some(b) => b.to_path_buf(),
            None => match std::env::var_os("XDG_RUNTIME_DIR") {
                Some(x) if Path::new(&x).is_dir() => PathBuf::from(x),
                _ => std::env::temp_dir(),
            },
        };
        let dir = base.join(format!("{DIR_PREFIX}{}", std::process::id()));
        if dir.exists() {
            // A stale directory with our PID (PID reuse): never inherit it.
            fs::remove_dir_all(&dir).ok();
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("cannot create output dir {}", dir.display()))?;
        let h = OutputHandler { dir };
        h.cleanup_orphans(&base);
        Ok(h)
    }

    fn cleanup_orphans(&self, base: &Path) {
        let Ok(my_uid) = fs::metadata(&self.dir).map(|m| m.uid()) else {
            return;
        };
        let Ok(entries) = fs::read_dir(base) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(pid_str) = name.strip_prefix(DIR_PREFIX) else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            if pid == std::process::id() {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_dir() || meta.uid() != my_uid {
                continue;
            }
            if Path::new("/proc").join(pid.to_string()).exists() {
                continue;
            }
            let p = entry.path();
            info!("removing orphaned output dir {}", p.display());
            if let Err(e) = fs::remove_dir_all(&p) {
                warn!("cannot remove {}: {e}", p.display());
            }
        }
    }

    pub fn cleanup(&self) {
        if let Err(e) = fs::remove_dir_all(&self.dir) {
            warn!("cannot remove output dir {}: {e}", self.dir.display());
        }
    }

    /// Render an exec outcome, spilling to a file when it exceeds `max_inline`.
    pub fn format(&self, o: &ExecOutcome, max_inline: usize) -> String {
        let header = header_line(o);
        let total = o.stdout.len() + o.stderr.len();
        if total <= max_inline {
            return format_inline(&header, o);
        }
        match self.spill(o) {
            Ok(path) => format_spilled(&header, o, &path, total),
            Err(e) => {
                warn!("cannot write spill file: {e:#}; truncating inline");
                let mut t = o.clone();
                t.stdout.truncate(max_inline / 2);
                t.stderr.truncate(max_inline / 2);
                t.stdout_truncated |= t.stdout.len() < o.stdout.len();
                t.stderr_truncated |= t.stderr.len() < o.stderr.len();
                format_inline(&header, &t)
            }
        }
    }

    fn spill(&self, o: &ExecOutcome) -> Result<PathBuf> {
        let path = self.dir.join(format!("exec-{}.out", random_id()));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        if !o.stdout.is_empty() {
            f.write_all(b"--- stdout ---\n")?;
            f.write_all(&o.stdout)?;
            f.write_all(b"\n")?;
        }
        if !o.stderr.is_empty() {
            f.write_all(b"--- stderr ---\n")?;
            f.write_all(&o.stderr)?;
            f.write_all(b"\n")?;
        }
        Ok(path)
    }
}

fn header_line(o: &ExecOutcome) -> String {
    let mut h = match (o.exit_code, &o.signal) {
        (Some(c), None) => format!("[Exit Code: {c}]"),
        (_, Some(s)) => format!("[Killed by signal: {s}]"),
        (None, None) if o.timed_out => "[Exit Code: unknown]".to_string(),
        (None, None) => "[Exit Code: unknown (no status from server)]".to_string(),
    };
    h.push_str(&format!(" [Duration: {}]", fmt_duration(o.duration)));
    if o.timed_out {
        h.push_str(" [TIMED OUT: command was sent SIGTERM and the channel closed]");
    }
    if o.stdout_truncated || o.stderr_truncated {
        h.push_str(" [OUTPUT TRUNCATED at capture limit]");
    }
    h
}

fn format_inline(header: &str, o: &ExecOutcome) -> String {
    let mut s = String::from(header);
    if !o.stdout.is_empty() {
        s.push_str("\n\n--- stdout ---\n");
        s.push_str(&String::from_utf8_lossy(&o.stdout));
    }
    if !o.stderr.is_empty() {
        s.push_str("\n\n--- stderr ---\n");
        s.push_str(&String::from_utf8_lossy(&o.stderr));
    }
    if o.stdout.is_empty() && o.stderr.is_empty() {
        s.push_str("\n\n(no output)");
    }
    s
}

fn format_spilled(header: &str, o: &ExecOutcome, path: &Path, total: usize) -> String {
    let lines = count_lines(&o.stdout) + count_lines(&o.stderr);
    let mut s = String::from(header);
    s.push_str(&format!(
        "\n\nOutput exceeded the inline limit and was written to: {}\nTotal size: {total} bytes ({lines} lines)",
        path.display()
    ));
    if !o.stdout.is_empty() {
        s.push_str("\n\n--- stdout preview (first ~2KB) ---\n");
        s.push_str(&String::from_utf8_lossy(head(&o.stdout)));
        if o.stdout.len() > PREVIEW_BYTES * 2 {
            s.push_str("\n\n[...]\n\n--- stdout preview (last ~2KB) ---\n");
            s.push_str(&String::from_utf8_lossy(tail(&o.stdout)));
        }
    }
    if !o.stderr.is_empty() {
        s.push_str("\n\n--- stderr preview (first ~2KB) ---\n");
        s.push_str(&String::from_utf8_lossy(head(&o.stderr)));
    }
    s.push_str(
        "\n\nThe file is local to the MCP host. Search it with grep rather than reading it whole.",
    );
    s
}

fn head(b: &[u8]) -> &[u8] {
    &b[..b.len().min(PREVIEW_BYTES)]
}

fn tail(b: &[u8]) -> &[u8] {
    &b[b.len().saturating_sub(PREVIEW_BYTES)..]
}

fn count_lines(b: &[u8]) -> usize {
    if b.is_empty() {
        return 0;
    }
    let n = b.iter().filter(|&&c| c == b'\n').count();
    if b.last() != Some(&b'\n') { n + 1 } else { n }
}

pub fn fmt_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        let s = d.as_secs();
        format!("{}m{}s", s / 60, s % 60)
    }
}

pub fn random_id() -> String {
    let mut b = [0u8; 4];
    if getrandom::fill(&mut b).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        b = t.to_be_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Append to a capped buffer; returns true if anything was dropped.
pub fn append_capped(buf: &mut Vec<u8>, data: &[u8], cap: usize) -> bool {
    let room = cap.saturating_sub(buf.len());
    if data.len() <= room {
        buf.extend_from_slice(data);
        false
    } else {
        buf.extend_from_slice(&data[..room]);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> OutputHandler {
        let base = std::env::temp_dir().join(format!("ssh-btoim-out-test-{}", random_id()));
        fs::create_dir_all(&base).unwrap();
        OutputHandler::new(Some(&base)).unwrap()
    }

    #[test]
    fn inline_and_spill() {
        let h = handler();
        let o = ExecOutcome {
            stdout: b"hello\n".to_vec(),
            exit_code: Some(0),
            duration: Duration::from_millis(12),
            ..Default::default()
        };
        let s = h.format(&o, 1024);
        assert!(s.starts_with("[Exit Code: 0] [Duration: 12ms]"));
        assert!(s.contains("--- stdout ---\nhello"));

        let big = ExecOutcome {
            stdout: vec![b'x'; 10_000],
            stderr: b"warn".to_vec(),
            exit_code: Some(1),
            ..Default::default()
        };
        let s = h.format(&big, 1024);
        assert!(s.contains("was written to:"));
        assert!(s.contains("Total size: 10004 bytes"));
        let path = s
            .lines()
            .find_map(|l| l.strip_prefix("Output exceeded the inline limit and was written to: "))
            .unwrap();
        let meta = fs::metadata(path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        h.cleanup();
        assert!(!h.dir.exists());
    }

    #[test]
    fn timeout_and_signal_headers() {
        let o = ExecOutcome {
            timed_out: true,
            duration: Duration::from_secs(61),
            ..Default::default()
        };
        let h = header_line(&o);
        assert!(h.contains("[Exit Code: unknown]"));
        assert!(h.contains("TIMED OUT"));
        assert!(h.contains("1m1s"));
        let o = ExecOutcome {
            signal: Some("TERM".into()),
            exit_code: Some(143),
            ..Default::default()
        };
        assert!(header_line(&o).contains("[Killed by signal: TERM]"));
    }

    #[test]
    fn capped_append() {
        let mut b = Vec::new();
        assert!(!append_capped(&mut b, b"abc", 5));
        assert!(append_capped(&mut b, b"defg", 5));
        assert_eq!(b, b"abcde");
        assert!(append_capped(&mut b, b"x", 5));
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn line_counting() {
        assert_eq!(count_lines(b""), 0);
        assert_eq!(count_lines(b"a"), 1);
        assert_eq!(count_lines(b"a\n"), 1);
        assert_eq!(count_lines(b"a\nb"), 2);
    }
}
