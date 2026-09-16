#!/usr/bin/env python3
"""Drive ssh-btoim over stdio JSON-RPC and assert on tool behaviour."""
import json
import os
import signal
import subprocess
import sys
import time

WORK = os.environ["E2E_WORK"]
BIN = os.environ["E2E_BIN"]
ME = os.environ["E2E_ME"]


class Mcp:
    def __init__(self):
        self.p = subprocess.Popen(
            [BIN, "--config", os.path.join(WORK, "config.toml")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=open(os.path.join(WORK, "server.log"), "wb"),
            env={**os.environ, "SSH_BTOIM_LOG": "debug", "SSH_AUTH_SOCK": "/nonexistent"},
        )
        self.n = 0

    def request(self, method, params=None, timeout=60):
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            msg["params"] = params
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("server closed stdout")
            obj = json.loads(line)
            if obj.get("id") == self.n:
                if "error" in obj:
                    raise RuntimeError(f"{method}: {obj['error']}")
                return obj["result"]
        raise RuntimeError(f"{method}: timeout")

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()

    def call(self, tool, args=None, timeout=60):
        r = self.request("tools/call", {"name": tool, "arguments": args or {}}, timeout)
        text = "\n".join(c.get("text", "") for c in r.get("content", []))
        return bool(r.get("isError", False)), text

    def close(self):
        self.p.stdin.close()
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()


def check(cond, what, detail=""):
    status = "ok  " if cond else "FAIL"
    print(f"  [{status}] {what}")
    if detail:
        for line in detail.strip().splitlines()[:12]:
            print(f"         | {line}")
    if not cond:
        sys.exit(1)


m = Mcp()
init = m.request("initialize", {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "e2e", "version": "0"},
})
m.notify("notifications/initialized")
check(init["serverInfo"]["name"] == "ssh-btoim", "initialize")

if os.environ.get("E2E_MODE") == "wrong-destination":
    err, text = m.call("ssh_exec", {"host": "testbox", "command": "true"})
    check(err and "offers no key usable" in text,
          "key constrained to another destination is not offered after binding", text)
    m.close()
    print("driver: wrong-destination check passed")
    sys.exit(0)
check("run the e2e grant step" in init.get("instructions", ""), "instructions carry the configured grant hint")

tools = m.request("tools/list")["tools"]
names = sorted(t["name"] for t in tools)
check(names == ["ssh_disconnect", "ssh_exec", "ssh_list_hosts", "ssh_list_sessions", "ssh_upload"],
      "tool list", ", ".join(names))
exec_tool = next(t for t in tools if t["name"] == "ssh_exec")
ann = exec_tool.get("annotations", {})
check(ann.get("readOnlyHint") is False and ann.get("destructiveHint") is True,
      "ssh_exec annotated as write-capable", json.dumps(ann))
schema_props = exec_tool["inputSchema"]["properties"]
check(set(schema_props) == {"host", "command", "timeout_secs", "max_inline_bytes"},
      "ssh_exec exposes only alias/command/timeout/inline", ", ".join(schema_props))

err, text = m.call("ssh_list_hosts")
check(not err and "testbox" in text and "notallowed" not in text, "ssh_list_hosts lists only allowed aliases", text)
check("1 other alias" in text, "ssh_list_hosts counts unlisted aliases", text)

# Denied before any network activity.
err, text = m.call("ssh_exec", {"host": "notallowed", "command": "true"})
check(err and "not in allowed_hosts" in text, "alias outside the allow-list is denied", text)

# Host key mismatch and unknown host are refused (no TOFU).
err, text = m.call("ssh_exec", {"host": "badbox", "command": "true"})
check(err and "HOST KEY MISMATCH" in text, "changed host key is refused", text)
err, text = m.call("ssh_exec", {"host": "unknownbox", "command": "true"})
check(err and "not in" in text and "never trusts on first use" in text, "unknown host key is refused", text)

# The real thing: constrained agent key, session-bind, exec.
err, text = m.call("ssh_exec", {"host": "testbox", "command": "id -un; echo err >&2; exit 3"})
check(not err and "[Exit Code: 3]" in text and f"--- stdout ---\n{ME}" in text and "--- stderr ---\nerr" in text,
      "exec with constrained key: exit code, stdout and stderr", text)

err, text = m.call("ssh_list_sessions")
check(not err and "testbox" in text and "e2e-client-key" in text, "session listed with agent key comment", text)

# Persistent connection: second call reuses it (no new agent binding needed).
err, text = m.call("ssh_exec", {"host": "testbox", "command": "echo second"})
check(not err and "second" in text, "second exec on persistent connection", text)

# Large output spills to a file with preview.
err, text = m.call("ssh_exec", {"host": "testbox", "command": "seq 1 5000"})
check(not err and "was written to:" in text and "stdout preview (first ~2KB)" in text, "large output spilled", text)
spill = next(l.split(": ", 1)[1] for l in text.splitlines() if l.startswith("Output exceeded"))
check(os.path.exists(spill) and (os.stat(spill).st_mode & 0o777) == 0o600, "spill file is mode 0600")

# Timeout sends SIGTERM and returns partial output.
t0 = time.time()
err, text = m.call("ssh_exec", {"host": "testbox", "command": "echo partial; sleep 30", "timeout_secs": 2})
check(err and "TIMED OUT" in text and "partial" in text and time.time() - t0 < 10, "timeout enforced with partial output", text)

# Connection still usable after a timed-out command.
err, text = m.call("ssh_exec", {"host": "testbox", "command": "echo alive"})
check(not err and "alive" in text, "connection survives a timed-out command", text)

# Upload over SFTP.
target = os.path.join(WORK, "uploaded.txt")
err, text = m.call("ssh_upload", {"host": "testbox", "remote_path": target, "content": "hello\nworld\n", "permissions": "0640"})
check(not err and "Uploaded 12 bytes" in text, "sftp upload", text)
check(open(target).read() == "hello\nworld\n" and (os.stat(target).st_mode & 0o777) == 0o640, "uploaded content and mode")
err, text = m.call("ssh_upload", {"host": "testbox", "remote_path": "relative/path", "content": "x"})
check(err and "absolute" in text, "relative upload path rejected", text)

# Disconnect and reconnect (new agent binding on a fresh agent connection).
err, text = m.call("ssh_disconnect", {"host": "testbox"})
check(not err and "Disconnected from testbox" in text, "disconnect", text)
err, text = m.call("ssh_exec", {"host": "testbox", "command": "echo again"})
check(not err and "again" in text, "reconnect after disconnect", text)

# Revocation: kill the agent; the reaper must drop the live session.
agent_pid = int(subprocess.check_output(["pgrep", "-f", f"ssh-agent -a {WORK}/agent.sock"]).split()[0])
os.kill(agent_pid, signal.SIGTERM)
time.sleep(7)
err, text = m.call("ssh_list_sessions")
check(not err and "No active SSH sessions" in text, "sessions dropped after agent revocation", text)
err, text = m.call("ssh_exec", {"host": "testbox", "command": "true"})
check(err and "authorization is locked: run the e2e grant step" in text, "exec after revocation reports locked authorization with the hint", text)

m.close()
print("driver: all checks passed")
