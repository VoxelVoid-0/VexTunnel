#!/bin/bash
# ==========================================================
# ⚡ VexTunnel Suite - Fast Installer Launcher ⚡
# Author : VexElvn (https://github.com/VexElvn/VexTunnel)
# ==========================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$DIR/install/setup.sh" ]; then
    bash "$DIR/install/setup.sh" "$@"
else
    echo "==> Preparing VexTunnel installer..."
    TMP_SETUP=$(mktemp)
    curl -fsSL https://raw.githubusercontent.com/VexElvn/VexTunnel/main/install/setup.sh -o "$TMP_SETUP"
    bash "$TMP_SETUP" "$@"
    rm -f "$TMP_SETUP"
fi
