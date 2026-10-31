#!/bin/bash
# ==========================================================
# ⚡ VexTunnel Suite - One-Line Master Installer ⚡
# Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)
# Supported OS: Debian 10+ / Ubuntu 20.04+
# 100% Clean • Production-Ready • Zero-Backdoor
# ==========================================================
set -euo pipefail

# Visual Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

clear 2>/dev/null || true
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   ⚡ VEXTUNNEL SUITE v1.0 ⚡                 ║"
echo "║          Clean • Modern • Zero-Backdoor VPS Tunnel           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Root Check
if [ "${EUID}" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installer must be run as root!${NC}"
    exit 1
fi

# 2. Architecture Check
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ARCH_TYPE="x86_64 (Intel/AMD 64-bit)"
        ;;
    aarch64|arm64)
        ARCH_TYPE="ARM64 (aarch64 / AWS Graviton / Oracle Ampere)"
        ;;
    armv7l|armv8l)
        ARCH_TYPE="ARM32 ($ARCH)"
        ;;
    *)
        echo -e "${RED}[ERROR] Architecture $ARCH is not supported. Please use x86_64, amd64, or aarch64.${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}==> Detected CPU Architecture: ${CYAN}${BOLD}${ARCH_TYPE}${NC}"

REPO_URL="https://github.com/VoxelVoid-0/VexTunnel.git"
INSTALL_DIR="/etc/vextunnel"

echo -e "${GREEN}==> [1/3] Preparing system environment & dependencies...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git curl wget tar unzip

# 3. Clone or Update Repository
echo -e "${GREEN}==> [2/3] Fetching latest VexTunnel codebase...${NC}"
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${CYAN}==> Existing installation found in $INSTALL_DIR. Updating...${NC}"
    cd "$INSTALL_DIR"
    git fetch origin main
    git reset --hard origin/main
else
    # Preserve any existing database if re-installing
    [ -f "$INSTALL_DIR/vextunnel.db" ] && cp "$INSTALL_DIR/vextunnel.db" /tmp/vextunnel.db.bak 2>/dev/null || true
    rm -rf "$INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
    [ -f /tmp/vextunnel.db.bak ] && cp -n /tmp/vextunnel.db.bak "$INSTALL_DIR/vextunnel.db" 2>/dev/null && rm -f /tmp/vextunnel.db.bak || true
fi

cd "$INSTALL_DIR"
chmod +x install/*.sh install.sh cli/menu.py core/*.py 2>/dev/null || true

# 4. Run Core Component Setup
echo -e "${GREEN}==> [3/3] Deploying services and hardening configuration...${NC}"
bash "$INSTALL_DIR/install/setup.sh"
