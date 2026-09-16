//! ssh-btoim: SSH But This One Is Mine.
//!
//! An MCP server that lets an LLM agent run commands on a fixed allow-list
//! of hosts, authenticating only through a human-granted ssh-agent key that
//! is bound to each session with the OpenSSH `session-bind@openssh.com`
//! extension so destination constraints stay effective.

mod agent;
mod audit;
mod config;
mod known_hosts;
mod manager;
mod output;
mod ssh;
mod sshconfig;
mod tools;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::audit::Audit;
use crate::config::Config;
use crate::manager::Manager;
use crate::output::OutputHandler;
use crate::sshconfig::SshConfig;
use crate::tools::SshServer;

const USAGE: &str = "usage: ssh-btoim [--config PATH] [--check] [--version]

  --config PATH  configuration file (default: $SSH_BTOIM_CONFIG, then
                 $XDG_CONFIG_HOME/ssh-btoim/config.toml)
  --check        validate configuration, SSH config, and known_hosts, then exit
  --version      print version and exit

Logs go to stderr; set SSH_BTOIM_LOG=debug for more detail.";

struct Args {
    config: Option<PathBuf>,
    check: bool,
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        config: None,
        check: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" | "-c" => {
                args.config = Some(PathBuf::from(
                    it.next().context("--config requires a path")?,
                ));
            }
            "--check" => args.check = true,
            "--version" | "-V" => {
                println!("ssh-btoim {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other:?}\n{USAGE}"),
        }
    }
    Ok(args)
}

/// Load and validate everything; fail closed on any inconsistency.
fn startup(args: &Args) -> Result<(Arc<Config>, Arc<SshConfig>)> {
    let path = match &args.config {
        Some(p) => p.clone(),
        None => config::default_config_path()?,
    };
    let cfg = Config::load(&path)?;

    let entries = known_hosts::count_entries(&cfg.known_hosts)?;
    if entries == 0 {
        bail!(
            "known_hosts {} has no usable entries; refusing to start with an empty trust store",
            cfg.known_hosts.display()
        );
    }
    let sshcfg = SshConfig::load(&cfg.ssh_config)?;
    for alias in &cfg.allowed_hosts {
        let h = sshcfg
            .resolve(alias)
            .with_context(|| format!("allowed host {alias:?} cannot be resolved"))?;
        info!(
            "allowed: {alias} -> {}@{}:{} (known_hosts name {})",
            h.user,
            h.hostname,
            h.port,
            h.known_hosts_name()
        );
    }
    if !cfg.agent_socket.exists() {
        warn!(
            "agent socket {} does not exist; connections will fail until a grant is active",
            cfg.agent_socket.display()
        );
    }
    info!(
        "config {}: {} allowed host(s), {} known_hosts entries, max age {:?}, idle {:?}",
        path.display(),
        cfg.allowed_hosts.len(),
        entries,
        cfg.max_connection_age,
        cfg.idle_timeout
    );
    Ok((Arc::new(cfg), Arc::new(sshcfg)))
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = term.recv() => info!("received SIGTERM"),
        _ = int.recv() => info!("received SIGINT"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // stdout carries MCP JSON-RPC; everything else goes to stderr.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("SSH_BTOIM_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let args = parse_args()?;
    let (cfg, sshcfg) = match startup(&args) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("ssh-btoim: {e:#}");
            std::process::exit(2);
        }
    };
    if args.check {
        println!("configuration OK");
        return Ok(());
    }

    let audit = Arc::new(Audit::open(&cfg.audit_log)?);
    let output = Arc::new(OutputHandler::new(cfg.temp_dir.as_deref())?);
    let manager = Manager::new(cfg.clone(), sshcfg.clone());
    let reaper = manager.spawn_reaper();

    let server = SshServer::new(cfg, sshcfg, manager.clone(), output.clone(), audit);
    info!("starting MCP server on stdio");
    let service = server
        .serve(stdio())
        .await
        .context("MCP initialisation failed")?;

    tokio::select! {
        r = service.waiting() => {
            match r {
                Ok(reason) => info!("MCP session ended: {reason:?}"),
                Err(e) => warn!("MCP session error: {e}"),
            }
        }
        _ = shutdown_signal() => {}
    }

    reaper.abort();
    let n = manager.disconnect_all().await;
    if n > 0 {
        info!("closed {n} session(s)");
    }
    output.cleanup();
    Ok(())
}
