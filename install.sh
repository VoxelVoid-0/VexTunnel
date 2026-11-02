#!/bin/bash
# ==========================================================
# ⚡ VexTunnel Suite - Release-Centric Master Installer ⚡
# Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)
# Distribution: Official GitHub Releases (Clean Tarball Unpack)
# Supported OS: Debian 10+ / Ubuntu 20.04+
# 100% Clean • Production-Ready • Zero-Backdoor
# ==========================================================
set -euo pipefail

# Visual Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

clear 2>/dev/null || true
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  ⚡ VEXTUNNEL SUITE v1.3.0 ⚡                ║"
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

INSTALL_DIR="/etc/vextunnel"
REPO_OWNER="VoxelVoid-0"
REPO_NAME="VexTunnel"

# 3. Base Prerequisites Setup
echo -e "${GREEN}==> [1/3] Preparing system environment & core tools...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget tar gzip jq ca-certificates

# 4. Resolve Target Release Version (3-tier resolution)
TARGET_VERSION="${1:-${VERSION:-}}"
IS_DEV="${DEV:-false}"

if [ "$TARGET_VERSION" = "--dev" ] || [ "$IS_DEV" = "true" ]; then
    echo -e "${YELLOW}==> Development Channel requested. Deploying from latest 'main' branch...${NC}"
    apt-get install -y git
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR"
        git fetch origin main
        git reset --hard origin/main
    else
        [ -f "$INSTALL_DIR/vextunnel.db" ] && cp "$INSTALL_DIR/vextunnel.db" /tmp/vextunnel.db.bak 2>/dev/null || true
        rm -rf "$INSTALL_DIR"
        git clone "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" "$INSTALL_DIR"
        [ -f /tmp/vextunnel.db.bak ] && cp -n /tmp/vextunnel.db.bak "$INSTALL_DIR/vextunnel.db" 2>/dev/null && rm -f /tmp/vextunnel.db.bak || true
    fi
else
    if [ -z "$TARGET_VERSION" ]; then
        echo -e "${CYAN}==> Querying GitHub for latest official VexTunnel release...${NC}"
        # Tier 1: GitHub REST API
        TARGET_VERSION=$(curl -sSL --connect-timeout 5 "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
        
        # Tier 2: HTTP Redirect Location Header
        if [ -z "$TARGET_VERSION" ]; then
            TARGET_VERSION=$(curl -sSI --connect-timeout 5 "https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null | grep -i "location:" | awk -F'/' '{print $NF}' | tr -d '\r\n' || true)
        fi
        
        # Tier 3: Hardcoded fallback
        if [ -z "$TARGET_VERSION" ]; then
            TARGET_VERSION="v1.3.0"
        fi
    fi

    echo -e "${GREEN}==> Installing Official Stable Release: ${CYAN}${BOLD}${TARGET_VERSION}${NC}"
    
    # Create target directory
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/backups"
    mkdir -p "$INSTALL_DIR/certs"

    # Stop running services before file replacement
    systemctl stop vextunnel-ws vextunnel-wss vextunnel-ws-8880 vextunnel-enforcer 2>/dev/null || true

    # Download release tarball
    TAR_TMP="/tmp/vextunnel-${TARGET_VERSION}.tar.gz"
    DOWNLOAD_SUCCESS=false

    # Try release asset first
    ASSET_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${TARGET_VERSION}/vextunnel.tar.gz"
    if curl -sSL -f -o "$TAR_TMP" "$ASSET_URL" 2>/dev/null; then
        DOWNLOAD_SUCCESS=true
    fi

    # Fallback to GitHub auto-generated archive tarball
    if [ "$DOWNLOAD_SUCCESS" != "true" ]; then
        ARCHIVE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/tags/${TARGET_VERSION}.tar.gz"
        if curl -sSL -f -o "$TAR_TMP" "$ARCHIVE_URL" 2>/dev/null; then
            DOWNLOAD_SUCCESS=true
        fi
    fi

    # Fallback to main branch archive if tag not yet pushed
    if [ "$DOWNLOAD_SUCCESS" != "true" ]; then
        MAIN_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/main.tar.gz"
        echo -e "${YELLOW}==> Release asset pending, fetching from main archive...${NC}"
        curl -sSL -f -o "$TAR_TMP" "$MAIN_URL"
    fi

    echo -e "${GREEN}==> [2/3] Extracting clean release files to ${INSTALL_DIR}...${NC}"
    # Unpack tarball safely without touching .db, certs, or backups
    tar -xzf "$TAR_TMP" --strip-components=1 -C "$INSTALL_DIR" 2>/dev/null || tar -xzf "$TAR_TMP" -C "$INSTALL_DIR"
    rm -f "$TAR_TMP"

    # Save release version file
    echo "$TARGET_VERSION" > "$INSTALL_DIR/VERSION"
fi

cd "$INSTALL_DIR"
chmod +x install/*.sh cli/menu.py core/*.py 2>/dev/null || true

# 5. Run Component Setup
echo -e "${GREEN}==> [3/3] Deploying services, hardening firewall, and verifying configuration...${NC}"
bash "$INSTALL_DIR/install/setup.sh"
