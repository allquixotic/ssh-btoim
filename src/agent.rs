//! Minimal ssh-agent client.
//!
//! Speaks just enough of the OpenSSH agent protocol for this server:
//! identity listing, signing, and the `session-bind@openssh.com` extension
//! that lets a destination-constrained key (`ssh-add -h user@host`) be used.
//!
//! One agent connection is opened per SSH connection attempt. The binding
//! must be sent on the same agent connection that later signs, and the
//! agent refuses to rebind a connection that already authenticated, so the
//! connection is never shared or reused across SSH sessions.

use std::path::Path;

use russh::keys::HashAlg;
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_encoding::Encode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

const MAX_FRAME: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("cannot reach agent socket {path}: {source}")]
    Connect {
        path: String,
        source: std::io::Error,
    },
    #[error("agent I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("agent protocol error: {0}")]
    Protocol(String),
    #[error("agent refused: {0}")]
    Refused(String),
    #[error("SSH session went away while signing")]
    Send(#[from] russh::SendError),
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub blob: Vec<u8>,
    pub comment: String,
}

pub struct AgentClient {
    stream: UnixStream,
    bound: bool,
}

impl AgentClient {
    pub async fn connect(path: &Path) -> Result<AgentClient, AgentError> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|source| AgentError::Connect {
                path: path.display().to_string(),
                source,
            })?;
        Ok(AgentClient {
            stream,
            bound: false,
        })
    }

    async fn call(&mut self, payload: &[u8]) -> Result<Vec<u8>, AgentError> {
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).await?;

        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).await?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_FRAME {
            return Err(AgentError::Protocol(format!("bad reply length {len}")));
        }
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body).await?;
        Ok(body)
    }

    /// Keys the agent is willing to offer on this connection. After a
    /// session binding, OpenSSH only lists keys whose destination
    /// constraints permit the bound host.
    pub async fn list_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let reply = self.call(&[SSH_AGENTC_REQUEST_IDENTITIES]).await?;
        let mut r = Reader::new(&reply);
        match r.u8()? {
            SSH_AGENT_IDENTITIES_ANSWER => {}
            SSH_AGENT_FAILURE => {
                return Err(AgentError::Refused("identities request failed".into()));
            }
            t => return Err(AgentError::Protocol(format!("unexpected reply type {t}"))),
        }
        let n = r.u32()?;
        let mut out = Vec::new();
        for _ in 0..n {
            let blob = r.string()?.to_vec();
            let comment = String::from_utf8_lossy(r.string()?).into_owned();
            out.push(Identity { blob, comment });
        }
        Ok(out)
    }

    /// Bind this agent connection to an SSH session (`session-bind@openssh.com`).
    pub async fn session_bind(
        &mut self,
        host_key_blob: &[u8],
        session_id: &[u8],
        signature: &[u8],
    ) -> Result<(), AgentError> {
        if self.bound {
            return Err(AgentError::Protocol(
                "agent connection already bound".into(),
            ));
        }
        let mut msg = vec![SSH_AGENTC_EXTENSION];
        put_string(&mut msg, b"session-bind@openssh.com");
        put_string(&mut msg, host_key_blob);
        put_string(&mut msg, session_id);
        put_string(&mut msg, signature);
        msg.push(0); // is_forwarding = false: bind for user authentication
        let reply = self.call(&msg).await?;
        match reply.first() {
            Some(&SSH_AGENT_SUCCESS) => {
                self.bound = true;
                Ok(())
            }
            Some(&SSH_AGENT_EXTENSION_FAILURE) => Err(AgentError::Refused(
                "agent does not support session-bind@openssh.com (OpenSSH 8.9+ required)".into(),
            )),
            Some(&SSH_AGENT_FAILURE) => Err(AgentError::Refused(
                "agent rejected the session binding (bad host key signature or duplicate session)"
                    .into(),
            )),
            other => Err(AgentError::Protocol(format!(
                "unexpected session-bind reply {other:?}"
            ))),
        }
    }

    pub async fn sign(
        &mut self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>, AgentError> {
        let mut msg = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut msg, key_blob);
        put_string(&mut msg, data);
        msg.extend_from_slice(&flags.to_be_bytes());
        let reply = self.call(&msg).await?;
        let mut r = Reader::new(&reply);
        match r.u8()? {
            SSH_AGENT_SIGN_RESPONSE => Ok(r.string()?.to_vec()),
            SSH_AGENT_FAILURE => Err(AgentError::Refused(
                "agent refused to sign (key not permitted for this destination, or grant expired)"
                    .into(),
            )),
            t => Err(AgentError::Protocol(format!(
                "unexpected sign reply type {t}"
            ))),
        }
    }
}

impl russh::Signer for AgentClient {
    type Error = AgentError;

    async fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        let blob = match key {
            AgentIdentity::PublicKey { key, .. } => key
                .to_bytes()
                .map_err(|e| AgentError::Protocol(format!("cannot encode public key: {e}")))?,
            AgentIdentity::Certificate { certificate, .. } => certificate
                .encode_vec()
                .map_err(|e| AgentError::Protocol(format!("cannot encode certificate: {e}")))?,
        };
        let flags = match hash_alg {
            Some(HashAlg::Sha256) => SSH_AGENT_RSA_SHA2_256,
            Some(HashAlg::Sha512) => SSH_AGENT_RSA_SHA2_512,
            _ => 0,
        };
        // russh expects the buffer it handed us back, with the agent's
        // signature blob (`string type, string sig`) appended as one string.
        let sig = self.sign(&blob, &to_sign, flags).await?;
        let mut out = to_sign;
        put_string(&mut out, &sig);
        Ok(out)
    }
}

fn put_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn u8(&mut self) -> Result<u8, AgentError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| AgentError::Protocol("truncated reply".into()))?;
        self.pos += 1;
        Ok(b)
    }
    fn u32(&mut self) -> Result<u32, AgentError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| AgentError::Protocol("truncated reply".into()))?;
        self.pos += 4;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn string(&mut self) -> Result<&'a [u8], AgentError> {
        let len = self.u32()? as usize;
        let s = self
            .buf
            .get(self.pos..self.pos + len)
            .ok_or_else(|| AgentError::Protocol("truncated string in reply".into()))?;
        self.pos += len;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_roundtrip() {
        let mut buf = vec![SSH_AGENT_IDENTITIES_ANSWER];
        buf.extend_from_slice(&2u32.to_be_bytes());
        put_string(&mut buf, b"blob1");
        put_string(&mut buf, b"c1");
        put_string(&mut buf, b"blob2");
        put_string(&mut buf, b"");
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(r.u32().unwrap(), 2);
        assert_eq!(r.string().unwrap(), b"blob1");
        assert_eq!(r.string().unwrap(), b"c1");
        assert_eq!(r.string().unwrap(), b"blob2");
        assert_eq!(r.string().unwrap(), b"");
        assert!(r.u8().is_err());
    }

    #[test]
    fn truncated_string_is_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
        assert!(Reader::new(&buf).string().is_err());
    }
}
