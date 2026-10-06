#!/bin/sh
# Install into a throwaway, relative PREFIX and check the result:
#
# - the stable command is a symlink to an absolute, uniquely named executable
#   under PREFIX/libexec/ssh-btoim (a relative PREFIX must not produce a
#   relative or doubly rebased target);
# - reinstalling switches the symlink to a new executable and leaves the
#   previous one untouched (nothing is rebuilt or renamed in place);
# - on macOS the executable passes strict signature verification, is signed ad
#   hoc without the linker-signed flag, and carries no quarantine attribute;
# - the installed command launches.
#
# Set TMPDIR to choose where the throwaway prefix is created.
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/ssh-btoim-install-test.XXXXXX")
trap 'rm -rf "$test_root"' EXIT
trap 'exit 1' HUP INT TERM
test_root=$(CDPATH='' cd -- "$test_root" && pwd)

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

install_relative() {
	(cd "$test_root" && make -s -f "$repo_dir/Makefile" install PREFIX=prefix)
}

install_relative
installed="$test_root/prefix/bin/ssh-btoim"
[ -L "$installed" ] || fail "$installed is not a symlink to a versioned executable"
first=$(readlink "$installed")
case "$first" in
	"$test_root/prefix/libexec/ssh-btoim/ssh-btoim-"*) ;;
	*) fail "unexpected versioned target $first (want $test_root/prefix/libexec/ssh-btoim/ssh-btoim-*)" ;;
esac
{ [ -f "$first" ] && [ -x "$first" ]; } || fail "$first is not an executable file"

if [ "$(uname -s)" = "Darwin" ]; then
	codesign --verify --strict --verbose=4 "$first"
	details=$(codesign -d --verbose=4 "$first" 2>&1)
	case "$details" in
		*linker-signed*) fail "installed binary retained the linker-signed flag" ;;
	esac
	case "$details" in
		*Signature=adhoc*) ;;
		*) fail "installed binary is not signed ad hoc" ;;
	esac
	case "$details" in
		*Identifier=io.github.allquixotic.ssh-btoim*) ;;
		*) fail "installed binary has an unexpected signing identifier" ;;
	esac
	if xattr -p com.apple.quarantine "$first" >/dev/null 2>&1; then
		fail "installed binary is quarantined"
	fi
fi
"$installed" --version </dev/null >/dev/null 2>&1 || fail "installed command does not launch"

first_sum=$(cksum <"$first")
install_relative
second=$(readlink "$installed")
[ "$second" != "$first" ] || fail "reinstall reused the versioned path $first"
[ -x "$first" ] || fail "reinstall removed the previous executable"
[ "$(cksum <"$first")" = "$first_sum" ] || fail "reinstall modified the previous executable"
"$repo_dir/scripts/verify_binary.sh" "$second"
"$installed" --version </dev/null >/dev/null 2>&1 || fail "reinstalled command does not launch"

echo "install signature test passed ($(uname -s))"
