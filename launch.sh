#!/usr/bin/env bash
# Launch JetPort 5601 Manager
# Optional argument: device IP (default 192.168.10.2)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for required Python packages
python3 -c "import PyQt6, urllib3, pexpect" 2>/dev/null || {
    echo "Installing required packages..."
    pip3 install --user PyQt6 urllib3 pexpect
}

exec python3 "$SCRIPT_DIR/jetport.py" "$@"
