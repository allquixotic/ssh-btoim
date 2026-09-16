//! Server configuration.
//!
//! Everything security-relevant is fixed here, by the operator, and never by
//! the model calling the tools: which aliases are reachable, which agent
//! socket signs, which known_hosts file is authoritative, and how long a
//! connection may live.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// Unix socket of the ssh-agent that holds the (constrained) key.
    agent_socket: PathBuf,
    /// Pre-verified known_hosts file. Never written to.
    known_hosts: PathBuf,
    /// Concrete `Host` aliases from the SSH config that may be contacted.
    allowed_hosts: Vec<String>,
    /// OpenSSH client config to resolve aliases with. Default: ~/.ssh/config
    ssh_config: Option<PathBuf>,
    /// JSONL audit log. Default: ~/.local/state/ssh-btoim/audit.jsonl
    audit_log: Option<PathBuf>,
    /// Directory for large-output spill files. Default: $XDG_RUNTIME_DIR or /tmp
    temp_dir: Option<PathBuf>,
    /// What to tell the model when no agent grant is active, e.g. the name of
    /// the local command a human must run.
    grant_hint: Option<String>,
    #[serde(default = "d_connect_timeout")]
    connect_timeout_secs: u64,
    #[serde(default = "d_max_age")]
    max_connection_age_secs: u64,
    #[serde(default = "d_idle")]
    idle_timeout_secs: u64,
    #[serde(default = "d_cmd_timeout")]
    default_command_timeout_secs: u64,
    #[serde(default = "d_max_cmd_timeout")]
    max_command_timeout_secs: u64,
    #[serde(default = "d_max_output")]
    max_output_bytes: usize,
    #[serde(default = "d_inline")]
    default_inline_bytes: usize,
    #[serde(default = "d_max_upload")]
    max_upload_bytes: usize,
    #[serde(default = "d_revoke")]
    revoke_check_interval_secs: u64,
}

fn d_connect_timeout() -> u64 {
    10
}
fn d_max_age() -> u64 {
    3600
}
fn d_idle() -> u64 {
    900
}
fn d_cmd_timeout() -> u64 {
    300
}
fn d_max_cmd_timeout() -> u64 {
    3600
}
fn d_max_output() -> usize {
    512 * 1024
}
fn d_inline() -> usize {
    16 * 1024
}
fn d_max_upload() -> usize {
    8 * 1024 * 1024
}
fn d_revoke() -> u64 {
    15
}

#[derive(Debug, Clone)]
pub struct Config {
    pub path: PathBuf,
    pub agent_socket: PathBuf,
    pub known_hosts: PathBuf,
    pub allowed_hosts: Vec<String>,
    pub ssh_config: PathBuf,
    pub audit_log: PathBuf,
    pub temp_dir: Option<PathBuf>,
    pub grant_hint: String,
    pub connect_timeout: Duration,
    pub max_connection_age: Duration,
    pub idle_timeout: Duration,
    pub default_command_timeout: Duration,
    pub max_command_timeout: Duration,
    pub max_output_bytes: usize,
    pub default_inline_bytes: usize,
    pub max_upload_bytes: usize,
    pub revoke_check_interval: Duration,
}

pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .context("HOME is not set to an absolute path")
}

pub fn expand_tilde(p: &Path) -> Result<PathBuf> {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        Ok(home_dir()?.join(rest))
    } else if s == "~" {
        home_dir()
    } else {
        Ok(p.to_path_buf())
    }
}

/// Locate the config file: explicit path, `$SSH_BTOIM_CONFIG`,
/// `$XDG_CONFIG_HOME/ssh-btoim/config.toml`, then `~/.config/ssh-btoim/config.toml`.
pub fn default_config_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("SSH_BTOIM_CONFIG") {
        return Ok(PathBuf::from(p));
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x),
        _ => home_dir()?.join(".config"),
    };
    Ok(base.join("ssh-btoim").join("config.toml"))
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "cannot read config {}; copy config.example.toml there and edit it",
                path.display()
            )
        })?;
        let raw: RawConfig = toml::from_str(&text)
            .with_context(|| format!("cannot parse config {}", path.display()))?;
        let home = home_dir()?;

        let agent_socket = expand_tilde(&raw.agent_socket)?;
        if !agent_socket.is_absolute() {
            bail!("agent_socket must be an absolute path");
        }
        let known_hosts = expand_tilde(&raw.known_hosts)?;
        if !known_hosts.is_absolute() {
            bail!("known_hosts must be an absolute path");
        }
        let ssh_config = match raw.ssh_config {
            Some(p) => expand_tilde(&p)?,
            None => home.join(".ssh").join("config"),
        };
        let audit_log = match raw.audit_log {
            Some(p) => expand_tilde(&p)?,
            None => {
                let base = match std::env::var_os("XDG_STATE_HOME") {
                    Some(x) if !x.is_empty() => PathBuf::from(x),
                    _ => home.join(".local").join("state"),
                };
                base.join("ssh-btoim").join("audit.jsonl")
            }
        };
        let temp_dir = raw.temp_dir.map(|p| expand_tilde(&p)).transpose()?;

        if raw.allowed_hosts.is_empty() {
            bail!("allowed_hosts must list at least one SSH config alias");
        }
        let mut allowed_hosts = Vec::new();
        for alias in raw.allowed_hosts {
            if alias.is_empty() || alias.contains(['*', '?', '!', ' ', '/']) {
                bail!("allowed_hosts entry {alias:?} must be a concrete alias, not a pattern");
            }
            if allowed_hosts.contains(&alias) {
                bail!("allowed_hosts lists {alias:?} twice");
            }
            allowed_hosts.push(alias);
        }

        for (name, v) in [
            ("connect_timeout_secs", raw.connect_timeout_secs),
            ("max_connection_age_secs", raw.max_connection_age_secs),
            ("idle_timeout_secs", raw.idle_timeout_secs),
            (
                "default_command_timeout_secs",
                raw.default_command_timeout_secs,
            ),
            ("max_command_timeout_secs", raw.max_command_timeout_secs),
            ("revoke_check_interval_secs", raw.revoke_check_interval_secs),
        ] {
            if v == 0 {
                bail!("{name} must be greater than zero");
            }
        }
        if raw.default_command_timeout_secs > raw.max_command_timeout_secs {
            bail!("default_command_timeout_secs exceeds max_command_timeout_secs");
        }
        if raw.default_inline_bytes == 0 || raw.max_output_bytes == 0 || raw.max_upload_bytes == 0 {
            bail!("byte limits must be greater than zero");
        }

        Ok(Config {
            path: path.to_path_buf(),
            agent_socket,
            known_hosts,
            allowed_hosts,
            ssh_config,
            audit_log,
            temp_dir,
            grant_hint: raw
                .grant_hint
                .filter(|h| !h.trim().is_empty())
                .unwrap_or_else(|| {
                    "a human must load a key into the configured ssh-agent".to_string()
                }),
            connect_timeout: Duration::from_secs(raw.connect_timeout_secs),
            max_connection_age: Duration::from_secs(raw.max_connection_age_secs),
            idle_timeout: Duration::from_secs(raw.idle_timeout_secs),
            default_command_timeout: Duration::from_secs(raw.default_command_timeout_secs),
            max_command_timeout: Duration::from_secs(raw.max_command_timeout_secs),
            max_output_bytes: raw.max_output_bytes,
            default_inline_bytes: raw.default_inline_bytes,
            max_upload_bytes: raw.max_upload_bytes,
            revoke_check_interval: Duration::from_secs(raw.revoke_check_interval_secs),
        })
    }

    pub fn is_allowed(&self, alias: &str) -> bool {
        self.allowed_hosts.iter().any(|a| a == alias)
    }

    /// Clamp a caller-supplied command timeout into the configured range.
    pub fn command_timeout(&self, requested: Option<u64>) -> Duration {
        match requested {
            None | Some(0) => self.default_command_timeout,
            Some(s) => Duration::from_secs(s).min(self.max_command_timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("config.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn loads_minimal_config() {
        let dir = tempdir();
        let p = write(
            &dir,
            r#"
agent_socket = "/run/agent.sock"
known_hosts = "/etc/kh"
allowed_hosts = ["a", "b"]
"#,
        );
        let c = Config::load(&p).unwrap();
        assert_eq!(c.allowed_hosts, vec!["a", "b"]);
        assert_eq!(c.max_connection_age, Duration::from_secs(3600));
        assert!(c.is_allowed("a"));
        assert!(!c.is_allowed("c"));
        assert_eq!(c.command_timeout(None), Duration::from_secs(300));
        assert_eq!(c.command_timeout(Some(99_999)), Duration::from_secs(3600));
        assert_eq!(c.command_timeout(Some(5)), Duration::from_secs(5));
    }

    #[test]
    fn rejects_patterns_and_unknown_keys() {
        let dir = tempdir();
        let p = write(
            &dir,
            "agent_socket = \"/a\"\nknown_hosts = \"/k\"\nallowed_hosts = [\"web-*\"]\n",
        );
        assert!(Config::load(&p).is_err());
        let p = write(
            &dir,
            "agent_socket = \"/a\"\nknown_hosts = \"/k\"\nallowed_hosts = [\"x\"]\nbogus = 1\n",
        );
        assert!(Config::load(&p).is_err());
        let p = write(
            &dir,
            "agent_socket = \"/a\"\nknown_hosts = \"/k\"\nallowed_hosts = []\n",
        );
        assert!(Config::load(&p).is_err());
    }

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ssh-btoim-cfg-test-{}-{}",
            std::process::id(),
            crate::output::random_id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
