//! The MCP tool surface.
//!
//! The model chooses an *alias* and a *command*; everything else about how
//! the connection is made is fixed by the operator's configuration.

use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData as McpError, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;

use crate::audit::{Audit, AuditEvent};
use crate::config::Config;
use crate::manager::{Manager, SshError};
use crate::output::{OutputHandler, fmt_duration};
use crate::sshconfig::SshConfig;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecParams {
    /// Host alias. Must be one of the aliases returned by ssh_list_hosts.
    pub host: String,
    /// Shell command to run on the remote host. Each call runs in a fresh
    /// non-interactive shell; chain with `&&` or `;` to keep state.
    pub command: String,
    /// Timeout in seconds. Omit for the server default; values above the
    /// configured maximum are clamped.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Bytes of output to return inline. Larger output is written to a local
    /// file and a preview plus path is returned instead.
    #[serde(default)]
    pub max_inline_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UploadParams {
    /// Host alias. Must be one of the aliases returned by ssh_list_hosts.
    pub host: String,
    /// Absolute path on the remote host. The file is created or truncated.
    pub remote_path: String,
    /// Text content to write.
    pub content: String,
    /// Octal permissions, e.g. "0644" (default) or "0755".
    #[serde(default)]
    pub permissions: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DisconnectParams {
    /// Alias to disconnect. Omit to disconnect every active session.
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Clone)]
pub struct SshServer {
    cfg: Arc<Config>,
    sshcfg: Arc<SshConfig>,
    manager: Arc<Manager>,
    output: Arc<OutputHandler>,
    audit: Arc<Audit>,
}

fn text_ok(s: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s.into())])
}

fn text_err(s: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(s.into())])
}

#[tool_router]
impl SshServer {
    pub fn new(
        cfg: Arc<Config>,
        sshcfg: Arc<SshConfig>,
        manager: Arc<Manager>,
        output: Arc<OutputHandler>,
        audit: Arc<Audit>,
    ) -> Self {
        SshServer {
            cfg,
            sshcfg,
            manager,
            output,
            audit,
        }
    }

    #[tool(
        name = "ssh_exec",
        description = "Run a shell command on an allowed remote host over SSH. Returns exit code, duration, stdout and stderr as separate sections. The connection persists across calls until it expires or the agent grant is revoked. This can change remote state: treat it as a write operation.",
        annotations(
            title = "Run command over SSH",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn ssh_exec(
        &self,
        Parameters(p): Parameters<ExecParams>,
    ) -> Result<CallToolResult, McpError> {
        if p.host.trim().is_empty() {
            return Ok(text_err("host is required"));
        }
        if p.command.trim().is_empty() {
            return Ok(text_err("command is required"));
        }
        let timeout = self.cfg.command_timeout(p.timeout_secs);
        let inline = p
            .max_inline_bytes
            .filter(|&n| n > 0)
            .unwrap_or(self.cfg.default_inline_bytes)
            .min(self.cfg.max_output_bytes);

        match self
            .manager
            .exec(&p.host, &p.command, timeout, self.cfg.max_output_bytes)
            .await
        {
            Ok((conn, o)) => {
                let outcome = if o.timed_out { "timeout" } else { "ok" };
                let mut ev = AuditEvent::new("ssh_exec", outcome).command(&p.command);
                ev.host = Some(&p.host);
                ev.user = Some(&conn.host.user);
                ev.hostname = Some(&conn.host.hostname);
                ev.exit_code = o.exit_code;
                ev.duration_ms = Some(o.duration.as_millis());
                ev.bytes = Some(o.stdout.len() + o.stderr.len());
                self.audit.record(&ev);
                let body = self.output.format(&o, inline);
                Ok(if o.timed_out {
                    text_err(body)
                } else {
                    text_ok(body)
                })
            }
            Err(e) => Ok(self.fail("ssh_exec", &p.host, Some(&p.command), None, e)),
        }
    }

    #[tool(
        name = "ssh_upload",
        description = "Write text content to a file on an allowed remote host over SFTP, creating or truncating it. Uses the persistent SSH connection.",
        annotations(
            title = "Upload file over SFTP",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn ssh_upload(
        &self,
        Parameters(p): Parameters<UploadParams>,
    ) -> Result<CallToolResult, McpError> {
        if p.host.trim().is_empty() {
            return Ok(text_err("host is required"));
        }
        if !p.remote_path.starts_with('/') || p.remote_path.contains('\0') {
            return Ok(text_err("remote_path must be an absolute path"));
        }
        if p.content.len() > self.cfg.max_upload_bytes {
            return Ok(text_err(format!(
                "content is {} bytes; the upload limit is {} bytes",
                p.content.len(),
                self.cfg.max_upload_bytes
            )));
        }
        let mode = match parse_mode(p.permissions.as_deref()) {
            Ok(m) => m,
            Err(e) => return Ok(text_err(e)),
        };
        let timeout = self.cfg.default_command_timeout;

        match self
            .manager
            .upload(&p.host, &p.remote_path, p.content.as_bytes(), mode, timeout)
            .await
        {
            Ok(conn) => {
                let mut ev = AuditEvent::new("ssh_upload", "ok");
                ev.host = Some(&p.host);
                ev.user = Some(&conn.host.user);
                ev.hostname = Some(&conn.host.hostname);
                ev.remote_path = Some(&p.remote_path);
                ev.bytes = Some(p.content.len());
                self.audit.record(&ev);
                Ok(text_ok(format!(
                    "Uploaded {} bytes to {}:{} (mode {:04o})",
                    p.content.len(),
                    p.host,
                    p.remote_path,
                    mode
                )))
            }
            Err(e) => Ok(self.fail("ssh_upload", &p.host, None, Some(&p.remote_path), e)),
        }
    }

    #[tool(
        name = "ssh_list_hosts",
        description = "List the host aliases this server is allowed to reach, with their resolved user, hostname, port, and whether a session is currently open.",
        annotations(
            title = "List allowed hosts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn ssh_list_hosts(&self) -> Result<CallToolResult, McpError> {
        let mut s = String::from("Allowed SSH hosts:\n\n");
        s.push_str(&format!(
            "  {:<20} {:<40} {:<14} {:<6} {}\n",
            "Alias", "HostName", "User", "Port", "Connected"
        ));
        s.push_str(&format!(
            "  {:<20} {:<40} {:<14} {:<6} {}\n",
            "-----", "--------", "----", "----", "---------"
        ));
        for alias in &self.cfg.allowed_hosts {
            match self.sshcfg.resolve(alias) {
                Ok(h) => {
                    let connected = if self.manager.is_connected(alias).await {
                        "yes"
                    } else {
                        "no"
                    };
                    s.push_str(&format!(
                        "  {:<20} {:<40} {:<14} {:<6} {}\n",
                        h.alias, h.hostname, h.user, h.port, connected
                    ));
                }
                Err(e) => s.push_str(&format!("  {:<20} (unresolvable: {e:#})\n", alias)),
            }
        }
        let unlisted = self
            .sshcfg
            .list_aliases()
            .into_iter()
            .filter(|a| !self.cfg.is_allowed(a))
            .count();
        if unlisted > 0 {
            s.push_str(&format!(
                "\n{unlisted} other alias(es) exist in the SSH config but are not allowed for this server.\n"
            ));
        }
        s.push_str(&format!(
            "\nConnections expire {} after they open and after {} idle. Authentication requires an active agent grant.",
            fmt_duration(self.cfg.max_connection_age),
            fmt_duration(self.cfg.idle_timeout)
        ));
        Ok(text_ok(s))
    }

    #[tool(
        name = "ssh_list_sessions",
        description = "Show the currently open SSH sessions with connection age, idle time, and time until forced expiry.",
        annotations(
            title = "List open sessions",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn ssh_list_sessions(&self) -> Result<CallToolResult, McpError> {
        let sessions = self.manager.list_sessions().await;
        if sessions.is_empty() {
            return Ok(text_ok("No active SSH sessions."));
        }
        let mut s = String::from("Active SSH sessions:\n\n");
        s.push_str(&format!(
            "  {:<20} {:<32} {:<14} {:<12} {:<12} {:<12} {}\n",
            "Alias", "HostName", "User", "Connected", "Idle", "Expires in", "Agent key"
        ));
        for x in sessions {
            s.push_str(&format!(
                "  {:<20} {:<32} {:<14} {:<12} {:<12} {:<12} {}\n",
                x.alias,
                format!("{}:{}", x.hostname, x.port),
                x.user,
                fmt_duration(x.connected_for),
                fmt_duration(x.idle_for),
                fmt_duration(x.expires_in),
                x.key_comment
            ));
        }
        Ok(text_ok(s))
    }

    #[tool(
        name = "ssh_disconnect",
        description = "Close an open SSH session, or all sessions when no host is given.",
        annotations(
            title = "Disconnect",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn ssh_disconnect(
        &self,
        Parameters(p): Parameters<DisconnectParams>,
    ) -> Result<CallToolResult, McpError> {
        match p.host.as_deref().map(str::trim).filter(|h| !h.is_empty()) {
            None => {
                let n = self.manager.disconnect_all().await;
                let ev = AuditEvent::new("ssh_disconnect", "ok");
                self.audit.record(&ev);
                Ok(text_ok(format!("Disconnected all {n} active session(s).")))
            }
            Some(alias) => {
                let closed = self.manager.disconnect(alias).await;
                let mut ev = AuditEvent::new("ssh_disconnect", "ok");
                ev.host = Some(alias);
                self.audit.record(&ev);
                Ok(if closed {
                    text_ok(format!("Disconnected from {alias}."))
                } else {
                    text_ok(format!("No active session for {alias}."))
                })
            }
        }
    }
}

impl SshServer {
    fn fail(
        &self,
        tool: &str,
        host: &str,
        command: Option<&str>,
        remote_path: Option<&str>,
        e: SshError,
    ) -> CallToolResult {
        let (outcome, msg) = match &e {
            SshError::Denied(m) => ("denied", m.clone()),
            SshError::Failed(err) => ("error", format!("SSH error: {err:#}")),
        };
        let mut ev = AuditEvent::new(tool, outcome);
        if let Some(c) = command {
            ev = ev.command(c);
        }
        ev.host = Some(host);
        ev.remote_path = remote_path;
        ev.error = Some(msg.clone());
        self.audit.record(&ev);
        text_err(msg)
    }
}

fn parse_mode(s: Option<&str>) -> Result<u32, String> {
    let Some(s) = s.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(0o644);
    };
    let digits = s.strip_prefix("0o").unwrap_or(s);
    let m = u32::from_str_radix(digits, 8)
        .map_err(|_| format!("permissions {s:?} is not an octal mode like 0644"))?;
    if m > 0o7777 {
        return Err(format!("permissions {s:?} is out of range"));
    }
    Ok(m)
}

#[tool_handler]
impl ServerHandler for SshServer {
    fn get_info(&self) -> ServerConfig {
        let instructions = format!(
            "ssh-btoim gives you SSH access to a fixed allow-list of hosts using a human-granted, \
             time-limited agent key. Use ssh_list_hosts to see what is reachable; only those aliases \
             work. Host keys must already be recorded in known_hosts; unknown or changed keys are \
             refused and cannot be overridden from here. If a call reports that authorization is \
             locked or the grant is missing, stop and tell the user ({}); do not try other \
             credentials. Commands time out after {} by default. ssh_exec and ssh_upload change \
             remote state; prefer read-only preflight commands first.",
            self.cfg.grant_hint,
            fmt_duration(Duration::from_secs(
                self.cfg.default_command_timeout.as_secs()
            ))
        );
        let mut info = ServerConfig::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::new("ssh-btoim", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(instructions);
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes() {
        assert_eq!(parse_mode(None).unwrap(), 0o644);
        assert_eq!(parse_mode(Some("")).unwrap(), 0o644);
        assert_eq!(parse_mode(Some("0755")).unwrap(), 0o755);
        assert_eq!(parse_mode(Some("600")).unwrap(), 0o600);
        assert_eq!(parse_mode(Some("0o640")).unwrap(), 0o640);
        assert!(parse_mode(Some("abc")).is_err());
        assert!(parse_mode(Some("77777")).is_err());
    }
}
