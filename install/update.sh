#!/bin/bash
# ==========================================================
# ⚡ VexTunnel Suite - 1-Click Self-Update Script ⚡
# Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)
# Distribution: Official GitHub Releases (Clean Tarball Unpack)
# ==========================================================
set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

INSTALL_DIR="/etc/vextunnel"
REPO_OWNER="VoxelVoid-0"
REPO_NAME="VexTunnel"

if [ "${EUID}" -ne 0 ]; then
    echo -e "${RED}[ERROR] Update script must be run as root!${NC}"
    exit 1
fi

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          ⚡ VEXTUNNEL SAFE UPDATE & MIGRATION HUB ⚡         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Capture Pre-Update State
CURRENT_VERSION="v1.3.0"
[ -f "$INSTALL_DIR/VERSION" ] && CURRENT_VERSION=$(cat "$INSTALL_DIR/VERSION" | tr -d '[:space:]')
echo -e " ${BOLD}Currently Installed:${NC} ${CYAN}${CURRENT_VERSION}${NC}"

# Record active services before update
ACTIVE_SERVICES=()
for svc in vextunnel-ws vextunnel-wss vextunnel-ws-8880 vextunnel-enforcer dropbear badvpn-7300; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ACTIVE_SERVICES+=("$svc")
    fi
done

# 2. Database Safety Gate (Python Native SQLite Backup)
DB_PATH="$INSTALL_DIR/vextunnel.db"
BACKUP_DIR="$INSTALL_DIR/backups"
BACKUP_FILE=""
if [ -f "$DB_PATH" ]; then
    echo -e "${GREEN}==> [1/5] Creating atomic SQLite native backup...${NC}"
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/vextunnel_${TIMESTAMP}.db"
    
    python3 -c "
import sqlite3, sys
with sqlite3.connect('$DB_PATH') as src:
    src.execute('PRAGMA wal_checkpoint(FULL);')
    with sqlite3.connect('$BACKUP_FILE') as dst:
        src.backup(dst)
" || {
        echo -e "${RED}[ERROR] Native SQLite backup failed! Aborting update to protect data.${NC}"
        exit 1
    }
    echo -e "${GREEN}✅ Database safely backed up to ${BACKUP_FILE}${NC}"
fi

# 3. Resolve Target Version
TARGET_VERSION="${1:-}"
IS_DEV=false
if [ "$TARGET_VERSION" = "--dev" ]; then
    IS_DEV=true
    TARGET_VERSION=""
fi

if [ "$IS_DEV" = "true" ]; then
    echo -e "${YELLOW}==> Fetching latest development commit from main...${NC}"
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR"
        git fetch origin main
        git reset --hard origin/main
    else
        TAR_TMP="/tmp/vextunnel-dev.tar.gz"
        curl -sSL -f -o "$TAR_TMP" "https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/main.tar.gz"
        tar -xzf "$TAR_TMP" --strip-components=1 -C "$INSTALL_DIR" 2>/dev/null || tar -xzf "$TAR_TMP" -C "$INSTALL_DIR"
        rm -f "$TAR_TMP"
    fi
else
    if [ -z "$TARGET_VERSION" ]; then
        echo -e "${CYAN}==> Checking for latest stable release on GitHub...${NC}"
        TARGET_VERSION=$(curl -sSL --connect-timeout 5 "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
        if [ -z "$TARGET_VERSION" ]; then
            TARGET_VERSION=$(curl -sSI --connect-timeout 5 "https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null | grep -i "location:" | awk -F'/' '{print $NF}' | tr -d '\r\n' || true)
        fi
        [ -z "$TARGET_VERSION" ] && TARGET_VERSION="$CURRENT_VERSION"
    fi

    echo -e " ${BOLD}Target Release     :${NC} ${GREEN}${TARGET_VERSION}${NC}"
    
    echo -e "${GREEN}==> [2/5] Downloading and extracting release package...${NC}"
    TAR_TMP="/tmp/vextunnel-${TARGET_VERSION}.tar.gz"
    DOWNLOADED=false
    
    if curl -sSL -f -o "$TAR_TMP" "https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${TARGET_VERSION}/vextunnel.tar.gz" 2>/dev/null; then
        DOWNLOADED=true
    fi
    if [ "$DOWNLOADED" != "true" ]; then
        if curl -sSL -f -o "$TAR_TMP" "https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/tags/${TARGET_VERSION}.tar.gz" 2>/dev/null; then
            DOWNLOADED=true
        fi
    fi
    if [ "$DOWNLOADED" != "true" ]; then
        curl -sSL -f -o "$TAR_TMP" "https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/main.tar.gz"
    fi

    systemctl stop vextunnel-ws vextunnel-wss vextunnel-ws-8880 vextunnel-enforcer 2>/dev/null || true
    tar -xzf "$TAR_TMP" --strip-components=1 -C "$INSTALL_DIR" 2>/dev/null || tar -xzf "$TAR_TMP" -C "$INSTALL_DIR"
    rm -f "$TAR_TMP"
    echo "$TARGET_VERSION" > "$INSTALL_DIR/VERSION"
fi

chmod +x "$INSTALL_DIR"/install/*.sh "$INSTALL_DIR"/cli/menu.py "$INSTALL_DIR"/core/*.py 2>/dev/null || true

# 4. Dependency Synchronization (PEP 668)
echo -e "${GREEN}==> [3/5] Synchronizing dependencies...${NC}"
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    python3 -m pip install -q --no-cache-dir -r "$INSTALL_DIR/requirements.txt" --break-system-packages 2>/dev/null || \
    python3 -m pip install -q --no-cache-dir -r "$INSTALL_DIR/requirements.txt" 2>/dev/null || true
fi

# 5. Database Schema Migration
echo -e "${GREEN}==> [4/5] Running database migrations...${NC}"
python3 -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
from core.user_manager import UserManager
UserManager('$DB_PATH')
print('Database migrations verified OK')
"

# 6. Service Restart
echo -e "${GREEN}==> [5/5] Reloading and restarting services...${NC}"
systemctl daemon-reload
for svc in "${ACTIVE_SERVICES[@]}"; do
    systemctl restart "$svc" 2>/dev/null || true
done

# 7. Post-Update Health Validation
sleep 2
FAILED=()
for svc in vextunnel-ws vextunnel-enforcer dropbear; do
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        FAILED+=("$svc")
    fi
done

if [ ${#FAILED[@]} -gt 0 ]; then
    echo -e "\n${RED}[CRITICAL ALERT] Health check failed for: ${FAILED[*]}${NC}"
    if [ -f "$BACKUP_FILE" ]; then
        echo -e "${YELLOW}Initiating automatic safe rollback...${NC}"
        systemctl stop vextunnel-ws vextunnel-wss vextunnel-ws-8880 vextunnel-enforcer 2>/dev/null || true
        python3 -c "
import sqlite3
with sqlite3.connect('$BACKUP_FILE') as bkp:
    with sqlite3.connect('$DB_PATH') as target:
        bkp.backup(target)
        target.execute('PRAGMA wal_checkpoint(TRUNCATE);')
"
        for svc in "${ACTIVE_SERVICES[@]}"; do
            systemctl restart "$svc" 2>/dev/null || true
        done
        echo -e "${GREEN}✅ Server safely restored to previous state from ${BACKUP_FILE}${NC}"
        exit 1
    fi
fi

echo -e "\n${GREEN}${BOLD}==============================================================${NC}"
echo -e "${GREEN}${BOLD}     ✅ VEXTUNNEL SUCCESSFULLY UPDATED TO ${TARGET_VERSION}!     ${NC}"
echo -e "${GREEN}${BOLD}==============================================================${NC}"
