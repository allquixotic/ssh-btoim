#!/bin/sh
# Remove macOS quarantine and provenance attributes from a binary. No-op
# elsewhere. Symlinks are followed, so passing the stable command clears the
# versioned executable it points at.
set -eu

binary=${1:?usage: clear_darwin_provenance.sh PATH}
if [ "$(uname -s)" != "Darwin" ]; then
	exit 0
fi

if xattr -p com.apple.quarantine "$binary" >/dev/null 2>&1; then
	xattr -d com.apple.quarantine "$binary"
fi
if xattr -p com.apple.provenance "$binary" >/dev/null 2>&1; then
	# macOS 26+ may immediately re-materialize this attribute, but removing it
	# refreshes taskgated's path-scoped provenance state for the new signature.
	xattr -d com.apple.provenance "$binary"
	# Let syspolicyd/taskgated observe the provenance transition before exec.
	sleep 1
fi
