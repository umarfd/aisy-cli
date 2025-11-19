#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "This uninstaller must be run as root." >&2
    exit 1
fi

TARGET="${1:-/usr/local/bin/aisy}"

if [[ -x "$TARGET" ]]; then
    rm -f "$TARGET"
    echo "Removed CLI wrapper at $TARGET"
else
    echo "Wrapper $TARGET not found (nothing to remove)."
fi

echo "Dependencies were left untouched."
echo "Uninstall completed."
