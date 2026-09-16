//! A small OpenSSH `ssh_config` reader.
//!
//! Only the keywords that decide *where* we connect are honoured:
//! `HostName`, `User`, `Port`, `HostKeyAlias`, and (to refuse them)
//! `ProxyJump` / `ProxyCommand`. `Host` blocks with wildcard and negated
//! patterns, `Match all`, and `Include` are supported with OpenSSH's
//! first-obtained-value-wins semantics. Any other `Match` block is treated as
//! never matching, with a warning, because we cannot evaluate its criteria.
//!
//! Authentication keywords (`IdentityFile`, `IdentityAgent`, ...) are
//! deliberately ignored: the only credential source is the configured agent.

use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use tracing::{debug, warn};

use crate::config::{expand_tilde, home_dir};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHost {
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub host_key_alias: Option<String>,
}

impl ResolvedHost {
    /// The name OpenSSH would look up in known_hosts for this host.
    pub fn known_hosts_name(&self) -> String {
        match &self.host_key_alias {
            Some(a) => a.clone(),
            None if self.port == 22 => self.hostname.clone(),
            None => format!("[{}]:{}", self.hostname, self.port),
        }
    }
}

#[derive(Debug, Clone)]
struct Pattern {
    negate: bool,
    text: String,
}

#[derive(Debug, Clone)]
struct Block {
    /// Empty for the implicit global block and for unsupported `Match` blocks.
    patterns: Vec<Pattern>,
    /// `true` for the implicit top block and `Match all`.
    always: bool,
    options: Vec<(String, String)>,
}

impl Block {
    fn matches(&self, alias: &str) -> bool {
        if self.always {
            return true;
        }
        let mut positive = false;
        for p in &self.patterns {
            if glob_match(&p.text, alias) {
                if p.negate {
                    return false;
                }
                positive = true;
            }
        }
        positive
    }
}

#[derive(Debug)]
struct Loaded {
    blocks: Vec<Block>,
    sources: Vec<(PathBuf, Option<SystemTime>)>,
}

pub struct SshConfig {
    path: PathBuf,
    state: RwLock<Loaded>,
}

impl SshConfig {
    pub fn load(path: &Path) -> Result<SshConfig> {
        let loaded = parse_tree(path)?;
        Ok(SshConfig {
            path: path.to_path_buf(),
            state: RwLock::new(loaded),
        })
    }

    fn reload_if_changed(&self) {
        let changed = {
            let st = self.state.read().unwrap_or_else(|e| e.into_inner());
            st.sources.iter().any(|(p, t)| mtime(p) != *t)
        };
        if !changed {
            return;
        }
        match parse_tree(&self.path) {
            Ok(new) => {
                debug!("reloaded SSH config {}", self.path.display());
                *self.state.write().unwrap_or_else(|e| e.into_inner()) = new;
            }
            Err(e) => warn!("SSH config changed but failed to reload: {e:#}"),
        }
    }

    pub fn resolve(&self, alias: &str) -> Result<ResolvedHost> {
        if alias.is_empty()
            || alias.contains(['*', '?', '!'])
            || alias.contains(char::is_whitespace)
        {
            bail!("{alias:?} is not a concrete host alias");
        }
        self.reload_if_changed();
        let st = self.state.read().unwrap_or_else(|e| e.into_inner());

        let mut hostname: Option<String> = None;
        let mut user: Option<String> = None;
        let mut port: Option<String> = None;
        let mut host_key_alias: Option<String> = None;
        let mut proxy: Option<(String, String)> = None;

        for block in st.blocks.iter().filter(|b| b.matches(alias)) {
            for (k, v) in &block.options {
                let slot = match k.as_str() {
                    "hostname" => &mut hostname,
                    "user" => &mut user,
                    "port" => &mut port,
                    "hostkeyalias" => &mut host_key_alias,
                    "proxyjump" | "proxycommand" => {
                        if proxy.is_none() {
                            proxy = Some((k.clone(), v.clone()));
                        }
                        continue;
                    }
                    _ => continue,
                };
                if slot.is_none() {
                    *slot = Some(v.clone());
                }
            }
        }

        if let Some((k, v)) = proxy
            && !v.eq_ignore_ascii_case("none")
        {
            let keyword = if k == "proxyjump" {
                "ProxyJump"
            } else {
                "ProxyCommand"
            };
            bail!(
                "host {alias} uses {keyword}, which this server does not support (direct connections only)"
            );
        }

        let hostname = match hostname {
            Some(h) => expand_tokens(&h, alias),
            None => alias.to_string(),
        };
        let user = match user {
            Some(u) => expand_tokens(&u, alias),
            None => std::env::var("USER").unwrap_or_else(|_| "root".to_string()),
        };
        let port: u16 = match port {
            Some(p) => p
                .parse()
                .with_context(|| format!("invalid Port {p:?} for host {alias}"))?,
            None => 22,
        };
        if port == 0 {
            bail!("invalid Port 0 for host {alias}");
        }
        let host_key_alias = host_key_alias.map(|h| expand_tokens(&h, alias));

        Ok(ResolvedHost {
            alias: alias.to_string(),
            hostname,
            user,
            port,
            host_key_alias,
        })
    }

    /// Concrete (non-wildcard) aliases declared in `Host` lines, sorted.
    pub fn list_aliases(&self) -> Vec<String> {
        self.reload_if_changed();
        let st = self.state.read().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<String> = Vec::new();
        for b in &st.blocks {
            for p in &b.patterns {
                if p.negate || p.text.contains(['*', '?']) || p.text.is_empty() {
                    continue;
                }
                if !out.contains(&p.text) {
                    out.push(p.text.clone());
                }
            }
        }
        out.sort();
        out
    }
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn expand_tokens(v: &str, alias: &str) -> String {
    // Only %h (the alias) and %% are meaningful for the keywords we resolve.
    v.replace("%%", "\u{0}")
        .replace("%h", alias)
        .replace('\u{0}', "%")
}

/// Case-insensitive glob with `*` and `?`, as OpenSSH matches host patterns.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    let t: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn parse_tree(path: &Path) -> Result<Loaded> {
    let mut loaded = Loaded {
        blocks: vec![Block {
            patterns: vec![],
            always: true,
            options: vec![],
        }],
        sources: vec![],
    };
    let mut current = 0usize;
    parse_file(path, &mut loaded, &mut current, 0)?;
    Ok(loaded)
}

fn parse_file(path: &Path, loaded: &mut Loaded, current: &mut usize, depth: usize) -> Result<()> {
    if depth > 16 {
        bail!("Include nesting too deep at {}", path.display());
    }
    loaded.sources.push((path.to_path_buf(), mtime(path)));
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && depth == 0 => {
            warn!(
                "SSH config {} does not exist; only bare hostnames resolve",
                path.display()
            );
            return Ok(());
        }
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = split_keyword(line) else {
            continue;
        };
        let key = key.to_ascii_lowercase();
        match key.as_str() {
            "host" => {
                let patterns = split_args(value)
                    .into_iter()
                    .map(|a| match a.strip_prefix('!') {
                        Some(rest) => Pattern {
                            negate: true,
                            text: rest.to_string(),
                        },
                        None => Pattern {
                            negate: false,
                            text: a,
                        },
                    })
                    .collect();
                loaded.blocks.push(Block {
                    patterns,
                    always: false,
                    options: vec![],
                });
                *current = loaded.blocks.len() - 1;
            }
            "match" => {
                let always = value.trim().eq_ignore_ascii_case("all");
                if !always {
                    warn!(
                        "{}: `Match {}` cannot be evaluated by ssh-btoim; treating it as never matching",
                        path.display(),
                        value.trim()
                    );
                }
                loaded.blocks.push(Block {
                    patterns: vec![],
                    always,
                    options: vec![],
                });
                *current = loaded.blocks.len() - 1;
            }
            "include" => {
                for pat in split_args(value) {
                    let expanded = expand_tilde(Path::new(&pat))?;
                    let full = if expanded.is_absolute() {
                        expanded
                    } else {
                        home_dir()?.join(".ssh").join(expanded)
                    };
                    let pattern = full.to_string_lossy().into_owned();
                    let mut files: Vec<PathBuf> = match glob::glob(&pattern) {
                        Ok(paths) => paths.filter_map(|p| p.ok()).collect(),
                        Err(e) => {
                            warn!("bad Include pattern {pattern}: {e}");
                            continue;
                        }
                    };
                    files.sort();
                    for f in files {
                        if f.is_file() {
                            parse_file(&f, loaded, current, depth + 1)?;
                        }
                    }
                }
            }
            _ => {
                loaded.blocks[*current]
                    .options
                    .push((key, unquote(value.trim()).to_string()));
            }
        }
    }
    Ok(())
}

fn split_keyword(line: &str) -> Option<(&str, &str)> {
    let idx = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = &line[..idx];
    let mut rest = &line[idx..];
    rest = rest.trim_start();
    if let Some(r) = rest.strip_prefix('=') {
        rest = r.trim_start();
    }
    Some((key, rest))
}

fn split_args(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for c in value.chars() {
        match c {
            '"' => in_quote = !in_quote,
            c if c.is_whitespace() && !in_quote => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn unquote(v: &str) -> &str {
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(body: &str) -> SshConfig {
        let d = std::env::temp_dir().join(format!(
            "ssh-btoim-sshcfg-{}-{}",
            std::process::id(),
            crate::output::random_id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("config");
        std::fs::write(&p, body).unwrap();
        SshConfig::load(&p).unwrap()
    }

    #[test]
    fn glob() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("web-*", "web-01"));
        assert!(!glob_match("web-*", "db-01"));
        assert!(glob_match("h?st", "HOST"));
        assert!(glob_match("*.example.com", "a.b.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
    }

    #[test]
    fn first_value_wins_and_globals_apply() {
        // OpenSSH semantics: the first obtained value wins, so a global
        // block *before* a host block overrides it, and one after does not.
        let c = cfg(
            "Host *\n  Port 2200\n\nHost box alias2\n  HostName 10.0.0.5\n  HostKeyAlias box-key\n  User alice\n\nHost *\n  User fallback\n",
        );
        let r = c.resolve("box").unwrap();
        assert_eq!(r.hostname, "10.0.0.5");
        assert_eq!(r.user, "alice");
        assert_eq!(r.port, 2200);
        assert_eq!(r.host_key_alias.as_deref(), Some("box-key"));
        assert_eq!(r.known_hosts_name(), "box-key");
        let r2 = c.resolve("alias2").unwrap();
        assert_eq!(r2.hostname, "10.0.0.5");
        let other = c.resolve("other").unwrap();
        assert_eq!(other.user, "fallback");
        assert_eq!(other.hostname, "other");
        assert_eq!(other.known_hosts_name(), "[other]:2200");
        assert_eq!(
            c.list_aliases(),
            vec!["alias2".to_string(), "box".to_string()]
        );
    }

    #[test]
    fn negation_and_proxy_refusal() {
        let c = cfg(
            "Host * !bastion\n  ProxyJump bastion\nHost bastion\n  HostName 1.2.3.4\nHost %h-token\n",
        );
        assert!(
            c.resolve("inner")
                .unwrap_err()
                .to_string()
                .contains("ProxyJump")
        );
        assert_eq!(c.resolve("bastion").unwrap().hostname, "1.2.3.4");
        assert!(c.resolve("web*").is_err());
        assert!(c.resolve("").is_err());
    }

    #[test]
    fn equals_syntax_quotes_and_tokens() {
        let c = cfg("Host \"my box\"\n  HostName=\"%h.internal\"\n  Port = 22\n");
        let r = c.resolve("my box").unwrap_err();
        // whitespace in aliases is rejected as non-concrete
        assert!(r.to_string().contains("concrete"));
        let c = cfg("Host mybox\n  HostName=%h.internal\n  User=%%literal\n");
        let r = c.resolve("mybox").unwrap();
        assert_eq!(r.hostname, "mybox.internal");
        assert_eq!(r.user, "%literal");
    }
}
