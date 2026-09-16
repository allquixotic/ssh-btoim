//! One SSH connection: strict host-key check, agent session binding,
//! agent-only authentication, command execution, and SFTP upload.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use russh::client::{self, Handle};
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, Sig};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use crate::agent::AgentClient;
use crate::config::Config;
use crate::known_hosts::{self, Verdict};
use crate::output::{ExecOutcome, append_capped};
use crate::sshconfig::ResolvedHost;

/// What the agent needs to bind its connection to this SSH session.
pub struct KexBinding {
    pub host_key_blob: Vec<u8>,
    pub session_id: Vec<u8>,
    pub signature: Vec<u8>,
}

struct ClientHandler {
    known_hosts: PathBuf,
    lookup: String,
    binding: Arc<Mutex<Option<KexBinding>>>,
}

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool> {
        let key = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            PublicKeyOrCertificate::Certificate(_) => bail!(
                "server for {} presented a certificate host key; only plain keys recorded in known_hosts are accepted",
                self.lookup
            ),
        };
        let blob = key.to_bytes().context("cannot encode server host key")?;
        let fp = key.fingerprint(HashAlg::Sha256);
        let path = self.known_hosts.display();
        match known_hosts::verify(&self.known_hosts, &self.lookup, &blob)? {
            Verdict::Trusted { line } => {
                debug!("host key for {} matches {path} line {line}", self.lookup);
                Ok(true)
            }
            Verdict::Unknown => bail!(
                "host key for {} ({} {fp}) is not in {path}. Verify the fingerprint out of band and record it (ssh-keyscan | ssh-keygen -H) before connecting; this server never trusts on first use",
                self.lookup,
                key.algorithm()
            ),
            Verdict::Changed { line } => bail!(
                "HOST KEY MISMATCH for {}: presented {} {fp}, which differs from {path} line {line}. This could be a man-in-the-middle attack. Refusing to connect",
                self.lookup,
                key.algorithm()
            ),
            Verdict::Revoked { line } => bail!(
                "host key for {} is REVOKED ({path} line {line}). Refusing to connect",
                self.lookup
            ),
        }
    }

    async fn kex_binding(
        &mut self,
        server_host_key_blob: &[u8],
        session_id: &[u8],
        server_signature: &[u8],
        _session: &mut client::Session,
    ) -> Result<()> {
        *self.binding.lock().unwrap_or_else(|e| e.into_inner()) = Some(KexBinding {
            host_key_blob: server_host_key_blob.to_vec(),
            session_id: session_id.to_vec(),
            signature: server_signature.to_vec(),
        });
        Ok(())
    }
}

pub struct Connection {
    pub host: ResolvedHost,
    handle: Handle<ClientHandler>,
    pub connected_at: Instant,
    pub deadline: Instant,
    last_used: Mutex<Instant>,
    pub key_comment: String,
}

impl Connection {
    pub async fn connect(cfg: &Config, host: ResolvedHost) -> Result<Connection> {
        let lookup = host.known_hosts_name();
        let binding = Arc::new(Mutex::new(None));
        let handler = ClientHandler {
            known_hosts: cfg.known_hosts.clone(),
            lookup: lookup.clone(),
            binding: binding.clone(),
        };
        let russh_cfg = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        });

        info!(
            "connecting to {} ({}@{}:{})",
            host.alias, host.user, host.hostname, host.port
        );
        let mut handle = tokio::time::timeout(
            cfg.connect_timeout,
            client::connect(russh_cfg, (host.hostname.as_str(), host.port), handler),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "connection to {} ({}:{}) timed out after {:?}",
                host.alias,
                host.hostname,
                host.port,
                cfg.connect_timeout
            )
        })?
        .with_context(|| {
            format!(
                "cannot connect to {} ({}:{})",
                host.alias, host.hostname, host.port
            )
        })?;

        let auth = tokio::time::timeout(
            cfg.connect_timeout,
            authenticate(cfg, &host, &lookup, &mut handle, &binding),
        )
        .await;
        let key_comment = match auth {
            Ok(Ok(comment)) => comment,
            Ok(Err(e)) => {
                let _ = handle
                    .disconnect(Disconnect::ByApplication, "authentication failed", "en")
                    .await;
                return Err(e);
            }
            Err(_) => {
                let _ = handle
                    .disconnect(Disconnect::ByApplication, "authentication timed out", "en")
                    .await;
                bail!(
                    "authentication to {} timed out after {:?}",
                    host.alias,
                    cfg.connect_timeout
                );
            }
        };

        let now = Instant::now();
        info!(
            "connected to {} using agent key {key_comment:?}",
            host.alias
        );
        Ok(Connection {
            host,
            handle,
            connected_at: now,
            deadline: now + cfg.max_connection_age,
            last_used: Mutex::new(now),
            key_comment,
        })
    }

    pub fn touch(&self) {
        *self.last_used.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    pub fn last_used(&self) -> Instant {
        *self.last_used.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Why this connection should no longer be used, if anything.
    pub fn stale_reason(&self, now: Instant, idle_timeout: Duration) -> Option<&'static str> {
        if self.is_closed() {
            Some("connection closed")
        } else if now >= self.deadline {
            Some("maximum connection age reached")
        } else if now.duration_since(self.last_used()) >= idle_timeout {
            Some("idle timeout")
        } else {
            None
        }
    }

    pub async fn close(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "ssh-btoim session closed", "en")
            .await;
    }

    /// Run `command` in a fresh exec channel. Output is capped at `cap` bytes
    /// per stream; on timeout the process is sent SIGTERM and the channel
    /// closed, and whatever was captured is returned with `timed_out` set.
    pub async fn exec(&self, command: &str, timeout: Duration, cap: usize) -> Result<ExecOutcome> {
        let mut ch = self
            .handle
            .channel_open_session()
            .await
            .context("cannot open a session channel")?;
        ch.exec(true, command)
            .await
            .context("exec request could not be sent")?;

        let start = Instant::now();
        let deadline = tokio::time::Instant::now() + timeout;
        let mut o = ExecOutcome::default();
        let mut exit_seen = false;
        let mut eof_seen = false;

        loop {
            let msg = match tokio::time::timeout_at(deadline, ch.wait()).await {
                Ok(m) => m,
                Err(_) => {
                    o.timed_out = true;
                    let _ = ch.signal(Sig::TERM).await;
                    let _ = ch.close().await;
                    break;
                }
            };
            match msg {
                Some(ChannelMsg::Data { data }) => {
                    o.stdout_truncated |= append_capped(&mut o.stdout, &data, cap);
                }
                Some(ChannelMsg::ExtendedData { data, ext }) => {
                    if ext == 1 {
                        o.stderr_truncated |= append_capped(&mut o.stderr, &data, cap);
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    o.exit_code = Some(exit_status as i32);
                    exit_seen = true;
                }
                Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                    let (name, num) = sig_info(&signal_name);
                    o.exit_code = num.map(|n| 128 + n);
                    o.signal = Some(name);
                    exit_seen = true;
                }
                Some(ChannelMsg::Failure) => bail!("server refused the exec request"),
                Some(ChannelMsg::Eof) => eof_seen = true,
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
            if exit_seen && eof_seen {
                let _ = ch.close().await;
                break;
            }
        }
        o.duration = start.elapsed();
        Ok(o)
    }

    /// Write `data` to `path` over SFTP with the given mode.
    pub async fn upload(
        &self,
        path: &str,
        data: &[u8],
        mode: u32,
        timeout: Duration,
    ) -> Result<()> {
        tokio::time::timeout(timeout, self.upload_inner(path, data, mode))
            .await
            .map_err(|_| anyhow!("upload timed out after {timeout:?}"))?
    }

    async fn upload_inner(&self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let ch = self
            .handle
            .channel_open_session()
            .await
            .context("cannot open a session channel")?;
        ch.request_subsystem(true, "sftp")
            .await
            .context("sftp subsystem request could not be sent")?;
        let sftp = SftpSession::new(ch.into_stream())
            .await
            .context("SFTP initialisation failed (is the sftp subsystem enabled on the server?)")?;

        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(mode);
        let mut file = sftp
            .open_with_flags_and_attributes(
                path,
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
                attrs,
            )
            .await
            .with_context(|| format!("cannot create {path}"))?;
        file.write_all(data)
            .await
            .with_context(|| format!("write to {path} failed"))?;
        file.close()
            .await
            .with_context(|| format!("closing {path} failed"))?;

        // The open() mode is subject to the server's umask; set it explicitly.
        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(mode);
        sftp.set_metadata(path, attrs)
            .await
            .with_context(|| format!("cannot set permissions on {path}"))?;
        if let Err(e) = sftp.close().await {
            debug!("sftp close: {e}");
        }
        Ok(())
    }
}

/// Bind the agent to this session, then try each key the agent still offers.
async fn authenticate(
    cfg: &Config,
    host: &ResolvedHost,
    lookup: &str,
    handle: &mut Handle<ClientHandler>,
    binding: &Arc<Mutex<Option<KexBinding>>>,
) -> Result<String> {
    let b = binding
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or_else(|| {
            anyhow!("key exchange finished without binding material (russh patch missing?)")
        })?;

    let mut agent = AgentClient::connect(&cfg.agent_socket).await.map_err(|e| {
        anyhow!(
            "{e}. No SSH agent grant is active; authorization is locked: {}",
            cfg.grant_hint
        )
    })?;
    debug!(
        "binding agent connection to session with {} ({} byte host key)",
        lookup,
        b.host_key_blob.len()
    );
    agent
        .session_bind(&b.host_key_blob, &b.session_id, &b.signature)
        .await
        .context("agent session binding failed")?;
    debug!("agent accepted session binding");

    let ids = agent
        .list_identities()
        .await
        .context("cannot list agent identities")?;
    debug!("agent offers {} identit(ies) for this session", ids.len());
    if ids.is_empty() {
        bail!(
            "the agent offers no key usable for {}@{lookup}; the grant is expired, revoked, or not scoped to this host",
            host.user
        );
    }

    let needs_rsa = ids
        .iter()
        .filter_map(|id| PublicKey::from_bytes(&id.blob).ok())
        .any(|pk| matches!(pk.algorithm(), Algorithm::Rsa { .. }));
    let rsa_hash = if !needs_rsa {
        None
    } else {
        match handle.best_supported_rsa_hash().await {
            Ok(Some(h)) => h,
            Ok(None) => Some(HashAlg::Sha512),
            Err(e) => {
                warn!("could not query server-sig-algs: {e}");
                Some(HashAlg::Sha512)
            }
        }
    };

    for id in ids {
        let Ok(pk) = PublicKey::from_bytes(&id.blob) else {
            debug!("skipping non-key agent identity {:?}", id.comment);
            continue;
        };
        let hash_alg = if matches!(pk.algorithm(), Algorithm::Rsa { .. }) {
            rsa_hash
        } else {
            None
        };
        debug!("offering agent key {:?} for {}", id.comment, host.user);
        match handle
            .authenticate_publickey_with(host.user.clone(), pk, hash_alg, &mut agent)
            .await
        {
            Ok(r) if r.success() => return Ok(id.comment),
            Ok(_) => debug!("server rejected key {:?} for {}", id.comment, host.user),
            Err(e) => debug!("agent would not sign with {:?}: {e}", id.comment),
        }
    }
    bail!(
        "authentication for {}@{} failed: the agent refused to sign or the server rejected every offered key",
        host.user,
        host.alias
    )
}

fn sig_info(s: &Sig) -> (String, Option<i32>) {
    let (name, num) = match s {
        Sig::HUP => ("HUP", 1),
        Sig::INT => ("INT", 2),
        Sig::QUIT => ("QUIT", 3),
        Sig::ILL => ("ILL", 4),
        Sig::ABRT => ("ABRT", 6),
        Sig::FPE => ("FPE", 8),
        Sig::KILL => ("KILL", 9),
        Sig::USR1 => ("USR1", 10),
        Sig::SEGV => ("SEGV", 11),
        Sig::PIPE => ("PIPE", 13),
        Sig::ALRM => ("ALRM", 14),
        Sig::TERM => ("TERM", 15),
        Sig::Custom(name) => return (name.clone(), None),
    };
    (name.to_string(), Some(num))
}
