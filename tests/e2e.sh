#!/usr/bin/env bash
# End-to-end test: throwaway sshd on 127.0.0.1, a fresh ssh-agent holding a
# destination-constrained key, and the MCP server driven over stdio.
#
# Requires: /usr/sbin/sshd, ssh-keygen, ssh-agent, ssh-add (OpenSSH >= 8.9),
# python3, and a built target/debug/ssh-btoim.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
bin=${SSH_BTOIM_BIN:-$root/target/debug/ssh-btoim}
port=${E2E_PORT:-22022}
work=$(mktemp -d "${TMPDIR:-/tmp}/ssh-btoim-e2e.XXXXXX")
chmod 700 "$work"
me=$(id -un)

cleanup() {
    status=$?
    set +e
    if [[ $status -ne 0 ]]; then
        echo "== FAILED (exit $status); server log:"; sed 's/\x1b\[[0-9;]*m//g' "$work/server.log" 2>/dev/null | tail -30
        echo "== sshd log:"; tail -10 "$work/sshd.log" 2>/dev/null
    fi
    [[ -n "${sshd_pid:-}" ]] && kill "$sshd_pid" 2>/dev/null
    [[ -n "${agent_pid:-}" ]] && kill "$agent_pid" 2>/dev/null
    [[ -n "${agent2_pid:-}" ]] && kill "$agent2_pid" 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

echo "== workdir $work"

# --- sshd -----------------------------------------------------------------
ssh-keygen -q -t ed25519 -N '' -f "$work/hostkey"
ssh-keygen -q -t ed25519 -N '' -C 'e2e-client-key' -f "$work/clientkey"
ssh-keygen -q -t ed25519 -N '' -C 'e2e-unrelated-key' -f "$work/otherkey"
cp "$work/clientkey.pub" "$work/authorized_keys"
cat > "$work/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $work/hostkey
AuthorizedKeysFile $work/authorized_keys
PidFile none
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
Subsystem sftp internal-sftp
LogLevel ERROR
PerSourcePenalties no
EOF
/usr/sbin/sshd -D -e -f "$work/sshd_config" 2>"$work/sshd.log" &
sshd_pid=$!
for _ in $(seq 1 50); do
    (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break
    sleep 0.1
done
if ! (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then
    echo "sshd did not start:"; cat "$work/sshd.log"; exit 1
fi
echo "== sshd listening on $port"

# --- trust store and ssh config -----------------------------------------
printf 'testbox %s\n' "$(cut -d' ' -f1,2 "$work/hostkey.pub")" > "$work/known_hosts"
# A second alias whose recorded key is WRONG, to prove mismatches are refused.
printf 'badbox %s\n' "$(cut -d' ' -f1,2 "$work/otherkey.pub")" >> "$work/known_hosts"
cat > "$work/ssh_config" <<EOF
Host *
    IdentitiesOnly yes
    IdentityFile $work/clientkey.pub
Host testbox
    HostName 127.0.0.1
    Port $port
    HostKeyAlias testbox
    User $me
Host badbox
    HostName 127.0.0.1
    Port $port
    HostKeyAlias badbox
    User $me
Host unknownbox
    HostName 127.0.0.1
    Port $port
    HostKeyAlias unknownbox
    User $me
Host notallowed
    HostName 127.0.0.1
    Port $port
    HostKeyAlias testbox
    User $me
EOF

# --- agent with a destination-constrained key ----------------------------
eval "$(ssh-agent -a "$work/agent.sock" -s)" >/dev/null
agent_pid=$SSH_AGENT_PID
SSH_AUTH_SOCK="$work/agent.sock" ssh-add -q -H "$work/known_hosts" -h "$me@testbox" "$work/clientkey"
echo "== agent holds: $(SSH_AUTH_SOCK="$work/agent.sock" ssh-add -l)"

# Sanity: the constraint really bites. OpenSSH itself must succeed for
# testbox and be refused for notallowed (different alias -> different
# permitted destination).
SSH_AUTH_SOCK="$work/agent.sock" ssh -F "$work/ssh_config" -o UserKnownHostsFile="$work/known_hosts" \
    -o StrictHostKeyChecking=yes testbox true
echo "== OpenSSH baseline with constrained key: OK"

# --- server config --------------------------------------------------------
cat > "$work/config.toml" <<EOF
agent_socket = "$work/agent.sock"
known_hosts = "$work/known_hosts"
ssh_config = "$work/ssh_config"
allowed_hosts = ["testbox", "badbox", "unknownbox"]
audit_log = "$work/audit.jsonl"
temp_dir = "$work"
connect_timeout_secs = 10
max_connection_age_secs = 3600
idle_timeout_secs = 600
default_command_timeout_secs = 20
max_command_timeout_secs = 60
default_inline_bytes = 4096
revoke_check_interval_secs = 1
grant_hint = "run the e2e grant step"
EOF

"$bin" --config "$work/config.toml" --check

# --- drive the MCP server -------------------------------------------------
export E2E_WORK="$work" E2E_BIN="$bin" E2E_ME="$me"
python3 "$here/e2e_driver.py"

# --- negative: key constrained to a different destination -----------------
# The agent may hold the key, but after session binding it must not offer
# or sign with it for testbox.
printf 'wrongbox %s\n' "$(cut -d' ' -f1,2 "$work/otherkey.pub")" >> "$work/known_hosts"
eval "$(ssh-agent -a "$work/agent2.sock" -s)" >/dev/null
agent2_pid=$SSH_AGENT_PID
SSH_AUTH_SOCK="$work/agent2.sock" ssh-add -q -H "$work/known_hosts" -h "$me@wrongbox" "$work/clientkey"
# Portable in-place edit: BSD sed (macOS) and GNU sed disagree on `-i`.
sed "s#/agent\\.sock\"#/agent2.sock\"#" "$work/config.toml" > "$work/config.toml.new"
mv "$work/config.toml.new" "$work/config.toml"
E2E_MODE=wrong-destination python3 "$here/e2e_driver.py"

echo "== audit log:"
cat "$work/audit.jsonl"
echo "== PASS"
