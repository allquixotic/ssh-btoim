#!/bin/sh
# Check that a built or installed binary is launchable. On macOS also require
# a strictly valid code signature that does not carry the linker-signed flag.
set -eu

binary=${1:?usage: verify_binary.sh PATH}
if [ "$(uname -s)" = "Darwin" ]; then
	codesign --verify --strict --verbose=4 "$binary"
	details=$(codesign -d --verbose=4 "$binary" 2>&1)
	case "$details" in
		*linker-signed*)
			echo "explicit signing failed: $binary retains the linker-signed flag" >&2
			exit 1
			;;
	esac
fi

# Exercise process startup (exec, signature checks, dynamic loading) without
# needing a configuration file.
version=$("$binary" --version </dev/null 2>/dev/null)
case "$version" in
	ssh-btoim\ *) ;;
	*)
		echo "$binary --version printed an unexpected result: $version" >&2
		exit 1
		;;
esac
