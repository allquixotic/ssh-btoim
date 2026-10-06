#!/bin/sh
# Install ssh-btoim behind a stable, atomically switched symlink.
#
# usage: install.sh DESTINATION [SOURCE]
#
# DESTINATION is the stable command, e.g. ~/.local/bin/ssh-btoim. The
# executable goes to PREFIX/libexec/ssh-btoim/ssh-btoim-<UTC time>-<pid>,
# where PREFIX is the parent of DESTINATION's directory. That absolute path is
# final before the binary is signed or launched and is never renamed or
# rewritten afterwards; DESTINATION is switched to it with an atomic symlink
# rename. (On macOS, taskgated can keep stale state for a pathname that is
# rebuilt in place, and Codex had the server killed because of it.)
#
# Without SOURCE this runs `cargo build --release --locked` and installs
# target/release/ssh-btoim (honouring CARGO_TARGET_DIR). With SOURCE it
# installs that prebuilt binary instead, e.g. one from dist/.
set -eu

destination=${1:?usage: install.sh DESTINATION [SOURCE]}
source_binary=${2:-}
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(dirname -- "$script_dir")

# `make install PREFIX=~/.local` passes the tilde through literally under
# shells that do not expand it in that position (zsh by default).
case "$destination" in
	\~/*) destination="$HOME/${destination#\~/}" ;;
esac

if [ -z "$source_binary" ]; then
	cargo build --release --locked --manifest-path "$repo_dir/Cargo.toml"
	source_binary="${CARGO_TARGET_DIR:-$repo_dir/target}/release/ssh-btoim"
fi
if [ ! -f "$source_binary" ] || [ ! -x "$source_binary" ]; then
	echo "install.sh: $source_binary is not an executable file" >&2
	exit 1
fi

base=$(basename -- "$destination")
destination_dir=$(dirname -- "$destination")
mkdir -p "$destination_dir"
# Resolve to an absolute path before deriving anything from it, so a relative
# PREFIX cannot produce a relative (and so doubly rebased) symlink target.
destination_dir=$(CDPATH='' cd -- "$destination_dir" && pwd)
destination="$destination_dir/$base"
prefix=$(dirname -- "$destination_dir")
store="$prefix/libexec/$base"
temporary_link="$destination_dir/.$base.link.$$"
versioned="$store/$base-$(date -u +%Y%m%d%H%M%S)-$$"

if [ -e "$versioned" ] || [ -L "$versioned" ]; then
	echo "install.sh: $versioned already exists; refusing to overwrite it" >&2
	exit 1
fi

keep_versioned=0
cleanup() {
	if [ "$keep_versioned" -eq 0 ]; then
		rm -f "$versioned"
	fi
	rm -f "$temporary_link"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

mkdir -p "$store"
install -m 0755 "$source_binary" "$versioned"
# A downloaded SOURCE may be quarantined, which would block the launch check.
"$script_dir/clear_darwin_provenance.sh" "$versioned"
"$script_dir/sign_darwin.sh" "$versioned"
ln -s "$versioned" "$temporary_link"
mv -f "$temporary_link" "$destination"
keep_versioned=1
"$script_dir/clear_darwin_provenance.sh" "$destination"
echo "installed $destination -> $versioned"
