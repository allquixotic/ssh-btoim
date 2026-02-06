# ssh-btoim

**SSH But This One Is Mine** — an MCP server that gives Claude persistent SSH access to remote hosts.

## What it does

ssh-btoim is a [Model Context Protocol](https://modelcontextprotocol.io/) server that lets Claude Code and Claude Desktop execute commands on remote hosts over SSH. It reads your existing `~/.ssh/config` and uses your ssh-agent and identity files — no separate configuration needed.

### Why not just use `ssh` in Bash?

- **No quoting headaches.** Commands are JSON parameters, so nested quotes, special characters, and multi-line strings just work.
- **Structured output.** Stdout, stderr, and exit code come back as separate fields instead of interleaved text.
- **Persistent connections.** The first command to a host opens a connection that stays open for the session. No reconnect overhead on every call.
- **Output overflow protection.** Large outputs (>16KB by default) are written to a temp file with a preview, keeping the LLM's context window clean.
- **File upload via SFTP.** Write files to remote hosts without pipe gymnastics.

## Tools

| Tool | Description |
|------|-------------|
| `ssh_exec` | Run a command on a remote host |
| `ssh_list_hosts` | List hosts from `~/.ssh/config` |
| `ssh_list_sessions` | Show active connections |
| `ssh_disconnect` | Close connections |
| `ssh_upload` | Upload file content via SFTP |

## Requirements

- Go 1.21+
- SSH config and keys that work with the standard `ssh` client (ssh-agent, identity files)

## Install

```bash
go build -o ssh-btoim .
cp ssh-btoim ~/.local/bin/
```

### Claude Code

```bash
claude mcp add --transport stdio --scope user ssh-btoim -- ~/.local/bin/ssh-btoim
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ssh-btoim": {
      "command": "/path/to/ssh-btoim"
    }
  }
}
```

## How it works

- Parses `~/.ssh/config` to discover hosts and resolve connection parameters (hostname, user, port, identity files).
- Authenticates via ssh-agent first, then falls back to identity files from your SSH config.
- Maintains one persistent `*ssh.Client` per host. Each command gets a fresh `ssh.Session` for clean isolation.
- Host key verification uses Trust-On-First-Use with `~/.ssh/known_hosts`. Unknown hosts are accepted and persisted; mismatched keys are rejected.
- Output under 16KB (configurable per-call) is returned inline. Larger output goes to `/tmp/ssh-btoim-<pid>/` with a head/tail preview. Orphaned temp dirs from crashed instances are cleaned up on startup.

## License

Apache 2.0 — see [LICENSE](LICENSE).
