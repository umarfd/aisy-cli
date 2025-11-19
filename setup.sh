#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "This installer must be run as root so that the wrapper can be restricted to privileged users." >&2
    exit 1
fi

TARGET="${1:-/usr/local/bin/aisy}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Updating package index and installing dependencies (python3, openssh-client, traceroute, isc-dhcp-client, netplan.io)..."
apt-get update -y
apt-get install -y python3 openssh-client traceroute isc-dhcp-client netplan.io >/dev/null 2>&1 || {
    echo "Failed to install required packages." >&2
    exit 1
}

cat >"$TARGET" <<EOF
#!/usr/bin/env bash
SCRIPT_DIR="$SCRIPT_DIR"
exec python3 "\$SCRIPT_DIR/aisy.py" "\$@"
EOF

chmod 750 "$TARGET"
chown root:root "$TARGET"

echo "Installed aisy CLI wrapper at $TARGET"
echo "Only root (or users in the root group) can execute it."
echo "Run the application with the command: aisy"
echo "Setup completed successfully."
