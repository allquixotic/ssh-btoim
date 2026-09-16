//! Strict known_hosts verification.
//!
//! The file is authoritative and read-only: a host key is accepted only when
//! an identical key is recorded for the looked-up name. Unknown hosts are
//! refused (no trust-on-first-use), changed keys are refused loudly, and
//! `@revoked` entries win over everything else. `@cert-authority` lines are
//! ignored because certificate host keys are not supported.
//!
//! Supported hostname forms: plain names, `[host]:port`, comma-separated
//! pattern lists with `*`/`?` wildcards and `!` negation, and hashed
//! `|1|salt|hash` entries.

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::sshconfig::glob_match;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An identical key is recorded for this name.
    Trusted { line: usize },
    /// No entry exists for this name (or only entries of other key types).
    Unknown,
    /// An entry of the same key type exists with a different key.
    Changed { line: usize },
    /// The presented key is explicitly revoked.
    Revoked { line: usize },
}

/// Compare the server's key blob (wire encoding) against `path` for `name`.
pub fn verify(path: &Path, name: &str, key_blob: &[u8]) -> Result<Verdict> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read known_hosts {}", path.display()))?;
    Ok(verify_text(&text, name, key_blob))
}

pub fn verify_text(text: &str, name: &str, key_blob: &[u8]) -> Verdict {
    let key_type = blob_type(key_blob);
    let mut trusted: Option<usize> = None;
    let mut changed: Option<usize> = None;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let Some(entry) = parse_line(raw) else {
            continue;
        };
        if !hosts_match(entry.hosts, name) {
            continue;
        }
        let Ok(blob) = B64.decode(entry.key_b64) else {
            continue;
        };
        match entry.marker {
            Some("revoked") => {
                if blob == key_blob {
                    return Verdict::Revoked { line: line_no };
                }
            }
            Some(_) => {
                // @cert-authority and unknown markers: not usable for plain keys.
            }
            None => {
                if blob == key_blob {
                    trusted.get_or_insert(line_no);
                } else if entry.key_type == key_type.as_deref().unwrap_or("") && changed.is_none() {
                    changed = Some(line_no);
                }
            }
        }
    }

    if let Some(line) = trusted {
        Verdict::Trusted { line }
    } else if let Some(line) = changed {
        Verdict::Changed { line }
    } else {
        Verdict::Unknown
    }
}

/// Number of usable (non-comment, well-formed) entries. Used at startup to
/// refuse an empty trust store.
pub fn count_entries(path: &Path) -> Result<usize> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read known_hosts {}", path.display()))?;
    Ok(text.lines().filter(|l| parse_line(l).is_some()).count())
}

struct Entry<'a> {
    marker: Option<&'a str>,
    hosts: &'a str,
    key_type: &'a str,
    key_b64: &'a str,
}

fn parse_line(raw: &str) -> Option<Entry<'_>> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let mut first = fields.next()?;
    let marker = if let Some(m) = first.strip_prefix('@') {
        first = fields.next()?;
        Some(m)
    } else {
        None
    };
    let key_type = fields.next()?;
    let key_b64 = fields.next()?;
    if !key_type.starts_with("ssh-")
        && !key_type.starts_with("ecdsa-")
        && !key_type.starts_with("sk-")
    {
        return None;
    }
    Some(Entry {
        marker,
        hosts: first,
        key_type,
        key_b64,
    })
}

fn hosts_match(hosts: &str, name: &str) -> bool {
    let mut positive = false;
    for pat in hosts.split(',') {
        if pat.is_empty() {
            continue;
        }
        if let Some(hashed) = pat.strip_prefix("|1|") {
            if hashed_match(hashed, name) {
                positive = true;
            }
            continue;
        }
        let (negate, pat) = match pat.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, pat),
        };
        if glob_match(pat, name) {
            if negate {
                return false;
            }
            positive = true;
        }
    }
    positive
}

fn hashed_match(rest: &str, name: &str) -> bool {
    let Some((salt_b64, hash_b64)) = rest.split_once('|') else {
        return false;
    };
    let (Ok(salt), Ok(hash)) = (B64.decode(salt_b64), B64.decode(hash_b64)) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&salt) else {
        return false;
    };
    mac.update(name.as_bytes());
    mac.verify_slice(&hash).is_ok()
}

/// The algorithm name embedded at the start of an SSH public key blob.
fn blob_type(blob: &[u8]) -> Option<String> {
    if blob.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let end = 4usize.checked_add(len)?;
    if end > blob.len() {
        return None;
    }
    std::str::from_utf8(&blob[4..end]).ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIGVjZUCM6bGgO4nKKtR4o1z5kcZ8Q2kWQpuNzkG3tOKh";
    const ED25519_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIC1hMlFYb0RKcDF2Q29VbzBlc2ZzMFFxQ3BrRHg5MEZ2";

    fn blob(b64: &str) -> Vec<u8> {
        B64.decode(b64).unwrap()
    }

    #[test]
    fn exact_match_is_trusted() {
        let kh = format!("box ssh-ed25519 {ED25519_A} comment\n");
        assert_eq!(
            verify_text(&kh, "box", &blob(ED25519_A)),
            Verdict::Trusted { line: 1 }
        );
        assert_eq!(
            verify_text(&kh, "other", &blob(ED25519_A)),
            Verdict::Unknown
        );
    }

    #[test]
    fn changed_key_is_reported() {
        let kh = format!("# comment\n\nbox,10.0.0.1 ssh-ed25519 {ED25519_A}\n");
        assert_eq!(
            verify_text(&kh, "box", &blob(ED25519_B)),
            Verdict::Changed { line: 3 }
        );
        assert_eq!(
            verify_text(&kh, "10.0.0.1", &blob(ED25519_A)),
            Verdict::Trusted { line: 3 }
        );
    }

    #[test]
    fn revoked_wins() {
        let kh = format!("box ssh-ed25519 {ED25519_A}\n@revoked box ssh-ed25519 {ED25519_A}\n");
        assert_eq!(
            verify_text(&kh, "box", &blob(ED25519_A)),
            Verdict::Revoked { line: 2 }
        );
    }

    #[test]
    fn negation_wildcards_and_ports() {
        let kh =
            format!("*.lan,!bad.lan ssh-ed25519 {ED25519_A}\n[box]:2222 ssh-ed25519 {ED25519_B}\n");
        assert_eq!(
            verify_text(&kh, "good.lan", &blob(ED25519_A)),
            Verdict::Trusted { line: 1 }
        );
        assert_eq!(
            verify_text(&kh, "bad.lan", &blob(ED25519_A)),
            Verdict::Unknown
        );
        assert_eq!(
            verify_text(&kh, "[box]:2222", &blob(ED25519_B)),
            Verdict::Trusted { line: 2 }
        );
        assert_eq!(verify_text(&kh, "box", &blob(ED25519_B)), Verdict::Unknown);
    }

    #[test]
    fn hashed_entries() {
        // Generated with: ssh-keygen -H for hostname "box"
        let salt = [7u8; 20];
        let mut mac = Hmac::<Sha1>::new_from_slice(&salt).unwrap();
        mac.update(b"box");
        let hash = mac.finalize().into_bytes();
        let kh = format!(
            "|1|{}|{} ssh-ed25519 {ED25519_A}\n",
            B64.encode(salt),
            B64.encode(hash)
        );
        assert_eq!(
            verify_text(&kh, "box", &blob(ED25519_A)),
            Verdict::Trusted { line: 1 }
        );
        assert_eq!(verify_text(&kh, "bax", &blob(ED25519_A)), Verdict::Unknown);
    }

    #[test]
    fn cert_authority_lines_are_ignored_and_counted() {
        let kh =
            format!("@cert-authority * ssh-ed25519 {ED25519_A}\nother ssh-ed25519 {ED25519_B}\n");
        assert_eq!(verify_text(&kh, "box", &blob(ED25519_A)), Verdict::Unknown);
        assert_eq!(kh.lines().filter(|l| parse_line(l).is_some()).count(), 2);
    }
}
