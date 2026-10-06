#!/bin/sh
# Re-sign a binary ad hoc on macOS, replacing the linker's signature, then
# verify it. Elsewhere this only verifies.
#
# The linker-signed ad hoc signature that ld64 applies is enough for a
# terminal, but Codex's taskgated rejected (killed) such binaries. An explicit
# `codesign --force --sign -` produces an ordinary ad hoc signature without the
# linker-signed flag. Sign the binary at its final, never-renamed path.
set -eu

binary=${1:?usage: sign_darwin.sh PATH}
if [ "$(uname -s)" = "Darwin" ]; then
	codesign --force --sign - --identifier io.github.allquixotic.ssh-btoim "$binary"
fi
"$(dirname -- "$0")/verify_binary.sh" "$binary"
