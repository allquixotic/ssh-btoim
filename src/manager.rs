//! Pool of live connections, one per allowed alias, with absolute and idle
//! expiry and a watcher that tears everything down when the agent grant goes
//! away.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::agent::AgentClient;
use crate::config::Config;
use crate::output::ExecOutcome;
use crate::ssh::Connection;
use crate::sshconfig::SshConfig;

#[derive(Debug)]
pub enum SshError {
    /// Policy refused the request before any network activity.
    Denied(String),
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for SshError {
    fn from(e: anyhow::Error) -> Self {
        SshError::Failed(e)
    }
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::Denied(m) => write!(f, "denied: {m}"),
            SshError::Failed(e) => write!(f, "{e:#}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub connected_for: Duration,
    pub idle_for: Duration,
    pub expires_in: Duration,
    pub key_comment: String,
}

pub struct Manager {
    cfg: Arc<Config>,
    sshcfg: Arc<SshConfig>,
    conns: Mutex<HashMap<String, Arc<Connection>>>,
    /// Per-alias lock so concurrent calls for one host share a single connect.
    locks: std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl Manager {
    pub fn new(cfg: Arc<Config>, sshcfg: Arc<SshConfig>) -> Arc<Manager> {
        Arc::new(Manager {
            cfg,
            sshcfg,
            conns: Mutex::new(HashMap::new()),
            locks: std::sync::Mutex::new(HashMap::new()),
        })
    }

    fn alias_lock(&self, alias: &str) -> Arc<Mutex<()>> {
        let mut m = self.locks.lock().unwrap_or_else(|e| e.into_inner());
        m.entry(alias.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub async fn get_or_connect(&self, alias: &str) -> Result<Arc<Connection>, SshError> {
        if !self.cfg.is_allowed(alias) {
            return Err(SshError::Denied(format!(
                "host {alias:?} is not in allowed_hosts ({}); ssh_list_hosts shows what is reachable",
                self.cfg.path.display()
            )));
        }
        let host = self.sshcfg.resolve(alias)?;

        let lock = self.alias_lock(alias);
        let _guard = lock.lock().await;

        let existing = self.conns.lock().await.get(alias).cloned();
        if let Some(c) = existing {
            let now = Instant::now();
            let stale = c
                .stale_reason(now, self.cfg.idle_timeout)
                .or(if c.host != host {
                    Some("ssh config changed")
                } else {
                    None
                });
            match stale {
                None => return Ok(c),
                Some(why) => {
                    info!("reconnecting to {alias}: {why}");
                    self.remove(alias, &c).await;
                }
            }
        }

        let c = Arc::new(Connection::connect(&self.cfg, host).await?);
        self.conns.lock().await.insert(alias.to_string(), c.clone());
        Ok(c)
    }

    async fn remove(&self, alias: &str, c: &Arc<Connection>) {
        let removed = {
            let mut m = self.conns.lock().await;
            match m.get(alias) {
                Some(cur) if Arc::ptr_eq(cur, c) => m.remove(alias),
                _ => None,
            }
        };
        if let Some(c) = removed {
            c.close().await;
        }
    }

    pub async fn exec(
        &self,
        alias: &str,
        command: &str,
        timeout: Duration,
        cap: usize,
    ) -> Result<(Arc<Connection>, ExecOutcome), SshError> {
        let c = self.get_or_connect(alias).await?;
        c.touch();
        match c.exec(command, timeout, cap).await {
            Ok(o) => Ok((c, o)),
            Err(e) if c.is_closed() => {
                warn!("connection to {alias} dropped ({e:#}); reconnecting once");
                self.remove(alias, &c).await;
                let c = self.get_or_connect(alias).await?;
                c.touch();
                let o = c.exec(command, timeout, cap).await?;
                Ok((c, o))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn upload(
        &self,
        alias: &str,
        path: &str,
        data: &[u8],
        mode: u32,
        timeout: Duration,
    ) -> Result<Arc<Connection>, SshError> {
        let c = self.get_or_connect(alias).await?;
        c.touch();
        c.upload(path, data, mode, timeout).await?;
        Ok(c)
    }

    pub async fn disconnect(&self, alias: &str) -> bool {
        let c = self.conns.lock().await.remove(alias);
        match c {
            Some(c) => {
                c.close().await;
                info!("disconnected from {alias}");
                true
            }
            None => false,
        }
    }

    pub async fn disconnect_all(&self) -> usize {
        let all: Vec<(String, Arc<Connection>)> = self.conns.lock().await.drain().collect();
        let n = all.len();
        for (alias, c) in all {
            c.close().await;
            info!("disconnected from {alias}");
        }
        n
    }

    pub async fn is_connected(&self, alias: &str) -> bool {
        self.conns
            .lock()
            .await
            .get(alias)
            .map(|c| !c.is_closed())
            .unwrap_or(false)
    }

    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let now = Instant::now();
        let mut out: Vec<SessionInfo> = self
            .conns
            .lock()
            .await
            .values()
            .map(|c| SessionInfo {
                alias: c.host.alias.clone(),
                hostname: c.host.hostname.clone(),
                user: c.host.user.clone(),
                port: c.host.port,
                connected_for: now.duration_since(c.connected_at),
                idle_for: now.duration_since(c.last_used()),
                expires_in: c.deadline.saturating_duration_since(now),
                key_comment: c.key_comment.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.alias.cmp(&b.alias));
        out
    }

    /// Background task: evict expired connections and drop everything the
    /// moment the agent grant disappears (socket gone, agent dead, or no keys).
    pub fn spawn_reaper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let tick = Duration::from_secs(5);
            let mut since_probe = Duration::ZERO;
            loop {
                tokio::time::sleep(tick).await;
                me.reap_expired().await;

                since_probe += tick;
                if since_probe >= me.cfg.revoke_check_interval {
                    since_probe = Duration::ZERO;
                    me.check_grant().await;
                }
            }
        })
    }

    async fn reap_expired(&self) {
        let now = Instant::now();
        let snapshot: Vec<(String, Arc<Connection>)> = self
            .conns
            .lock()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (alias, c) in snapshot {
            if let Some(why) = c.stale_reason(now, self.cfg.idle_timeout) {
                info!("closing connection to {alias}: {why}");
                self.remove(&alias, &c).await;
            }
        }
    }

    async fn check_grant(&self) {
        if self.conns.lock().await.is_empty() {
            return;
        }
        let ok = match AgentClient::connect(&self.cfg.agent_socket).await {
            Ok(mut a) => matches!(a.list_identities().await, Ok(ids) if !ids.is_empty()),
            Err(_) => false,
        };
        if !ok {
            let n = self.disconnect_all().await;
            warn!("agent grant is gone (socket unreachable or no keys); closed {n} session(s)");
        }
    }
}
