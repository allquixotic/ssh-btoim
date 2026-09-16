# ssh-btoim

**SSH But This One Is Mine** — a hardened [Model Context Protocol](https://modelcontextprotocol.io/)
server that gives Claude Code, Claude Desktop, Codex and other MCP clients
command execution and file upload on a fixed allow-list of hosts over SSH.

It is written in Rust on top of a lightly patched [russh](https://github.com/Eugeny/russh)
and is designed around one idea: the model picks an alias and a command, and
nothing else about how the connection is made is under its control.

## Security model

- **Agent-only authentication.** The only credential source is an ssh-agent
  socket named in the config. Private key files are never read, passwords are
  never used, and `$SSH_AUTH_SOCK` is ignored.
- **Session binding for constrained keys.** Every SSH connection opens its
  own agent connection and binds it with OpenSSH's
  `session-bind@openssh.com` extension before authenticating. That is what
  makes destination-constrained keys (`ssh-add -h user@host`) usable, so a
  human can grant "this user on these hosts, for this long" and the agent
  enforces it independently of this server.
- **Strict, read-only host key checking.** Host keys must already be in the
  configured `known_hosts` (plain, hashed, `[host]:port`, wildcard and
  `@revoked` entries are understood; `HostKeyAlias` is honoured). Unknown
  keys are refused, changed keys are refused loudly, and the file is never
  written. The server refuses to start if the trust store is empty.
- **Explicit host allow-list.** Only concrete aliases listed in
  `allowed_hosts` can be contacted; anything else is denied before any
  network activity. `ProxyJump`/`ProxyCommand` hosts are refused.
- **Bounded connection lifetime.** Each connection has an absolute maximum
  age and an idle timeout. A watcher re-checks the agent every few seconds
  and closes every session the moment the grant is revoked, expires, or the
  agent goes away.
- **Write-capable tools are labelled as such.** `ssh_exec` and `ssh_upload`
  carry MCP annotations marking them non-read-only and destructive.
- **Audit trail.** Every call (including denials) is appended to a
  mode-0600 JSONL log with host, user, command, exit code, duration and
  outcome.
- **Output hygiene.** Per-stream capture caps, per-call timeouts that
  SIGTERM the remote process, and spill files in a private 0700 directory
  for large output.

The tool parameters exposed to the model are exactly: alias, command,
timeout, inline-output size (exec); alias, absolute path, content,
permissions (upload); and alias (disconnect). There is no way to pass a
hostname, port, identity, known_hosts file or SSH option.

## Tools

| Tool | Description |
|------|-------------|
| `ssh_exec` | Run a command on an allowed host; returns exit code, duration, stdout and stderr |
| `ssh_upload` | Write text content to an absolute path over SFTP |
| `ssh_list_hosts` | Show the allowed aliases with resolved user/host/port and connection state |
| `ssh_list_sessions` | Show open sessions with age, idle time and time to forced expiry |
| `ssh_disconnect` | Close one or all sessions |

## Requirements

- Rust 1.89+ (`rustup` stable)
- An OpenSSH agent that supports `session-bind@openssh.com` (OpenSSH 8.9+)
- A pre-verified `known_hosts` file and an `ssh_config` with the aliases you
  want to expose

## Build and install

```sh
cargo build --release
install -m 755 target/release/ssh-btoim ~/.local/bin/
mkdir -p ~/.config/ssh-btoim
cp config.example.toml ~/.config/ssh-btoim/config.toml   # then edit it
ssh-btoim --check
```

`--check` validates the config, resolves every allowed alias through the SSH
config, and confirms the trust store is non-empty.

### Claude Code

```sh
claude mcp add --transport stdio --scope user ssh-btoim -- ~/.local/bin/ssh-btoim
```

### Claude Desktop

```json
{
  "mcpServers": {
    "ssh-btoim": { "command": "/home/you/.local/bin/ssh-btoim" }
  }
}
```

## Granting access

Load a key into the agent named by `agent_socket`, constrained to the
destinations you want and with a lifetime:

```sh
ssh-agent -a ~/.ssh/agent.sock
SSH_AUTH_SOCK=~/.ssh/agent.sock ssh-add -t 1h -H ~/.ssh/known_hosts \
    -h user@hostkeyalias-1 -h user@hostkeyalias-2 ~/.ssh/id_ed25519
```

Revoking is killing that agent (or `ssh-add -D`). Open sessions are closed
within `revoke_check_interval_secs`, and new connections fail with a message
telling the model that authorization is locked. Set `grant_hint` in the config
to the exact instruction the model should relay to the user (for example the
name of your grant script).

## Configuration

See [`config.example.toml`](config.example.toml). Paths accept `~/`. The
config is found via `--config`, `$SSH_BTOIM_CONFIG`, then
`$XDG_CONFIG_HOME/ssh-btoim/config.toml`.

Logging goes to stderr (`SSH_BTOIM_LOG=debug` for protocol-level detail).

## Testing

```sh
cargo test            # unit tests
tests/e2e.sh          # end to end: throwaway sshd + constrained agent key
```

The end-to-end script starts an unprivileged `sshd` on 127.0.0.1, an agent
holding a destination-constrained key, and drives the server over stdio. It
checks the allow-list, host-key refusal (unknown and changed), exec with
separate streams and exit codes, output spilling, timeouts, SFTP upload,
reconnect, revocation, and that a key constrained to a *different*
destination is not offered after binding.

## Vendored russh

`vendor/russh` carries a small patch that exposes the key-exchange material
needed for agent session binding. See [`patches/README.md`](patches/README.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
