#!/bin/bash
# ==========================================================
# ⚡ VexTunnel Suite - 1-Click Self-Update Engine (v6) ⚡
# Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)
# Distribution: Official GitHub Releases (Clean Tarball Unpack)
# ==========================================================
{
main() {
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
    CODE_SNAPSHOT="/tmp/vextunnel_code_rollback.tar.gz"

    if [ "${EUID}" -ne 0 ]; then
        echo -e "${RED}[ERROR] Update script must be run as root!${NC}"
        exit 1
    fi

    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║       ⚡ VEXTUNNEL SAFE UPDATE & MIGRATION HUB (v6) ⚡       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Phase 0: Pre-flight Safety Gates
    CURRENT_VERSION="v1.3.0"
    [ -f "$INSTALL_DIR/VERSION" ] && CURRENT_VERSION=$(cat "$INSTALL_DIR/VERSION" | tr -d '[:space:]')
    echo -e " ${BOLD}Currently Installed:${NC} ${CYAN}${CURRENT_VERSION}${NC}"

    # 1. Fail-closed Disk Space Check (>= 150 MB free)
    AVAILABLE_KB=$(df -P "$INSTALL_DIR" 2>/dev/null | tail -1 | awk '{print $4}')
    AVAILABLE_MB=$(( AVAILABLE_KB / 1024 ))
    echo -e " ${BOLD}Disk Space Check   :${NC} ${GREEN}${AVAILABLE_MB} MB Available (>= 150 MB required)${NC}"
    if [ "$AVAILABLE_MB" -lt 150 ]; then
        echo -e "${RED}[ABORT] Insufficient disk space (${AVAILABLE_MB} MB). Update halted to protect database.${NC}"
        exit 1
    fi

    # 2. Record pre-update active services
    ACTIVE_SERVICES=()
    for svc in vextunnel-ws vextunnel-wss vextunnel-ws-8880 vextunnel-enforcer dropbear badvpn-7300; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            ACTIVE_SERVICES+=("$svc")
        fi
    done

    # 3. Resolve Target Version
    TARGET_VERSION="${1:-}"
    IS_DEV=false
    if [ "$TARGET_VERSION" = "--dev" ]; then
        IS_DEV=true
        TARGET_VERSION=""
    fi

    if [ "$IS_DEV" = "true" ]; then
        echo -e " ${BOLD}Target Channel     :${NC} ${YELLOW}Development (main)${NC}"
    else
        if [ -z "$TARGET_VERSION" ]; then
            echo -e "${CYAN}==> Checking for latest official release on GitHub...${NC}"
            TARGET_VERSION=$(curl -sSL --connect-timeout 5 "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
            if [ -z "$TARGET_VERSION" ]; then
                TARGET_VERSION=$(curl -sSI --connect-timeout 5 "https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null | grep -i "location:" | awk -F'/' '{print $NF}' | tr -d '\r\n' || true)
            fi
            [ -z "$TARGET_VERSION" ] && TARGET_VERSION="$CURRENT_VERSION"
        fi
        echo -e " ${BOLD}Target Release     :${NC} ${GREEN}${TARGET_VERSION}${NC}"
    fi

    # Phase 1: Clean Service Stop & Staging Download
    echo -e "\n${BOLD}Starting automated 5-phase update pipeline (v6 - Clean Stop Standard)...${NC}"
    echo -e "${GREEN}==> [1/5] Cleanly stopping services & securing SQLite database...${NC}"

    # Clean stop upfront (3x-ui standard) to eliminate file swap race conditions & DB locks
    for svc in "${ACTIVE_SERVICES[@]}"; do
        systemctl stop "$svc" 2>/dev/null || true
    done

    # SQLite native online backup
    DB_PATH="$INSTALL_DIR/vextunnel.db"
    BACKUP_DIR="$INSTALL_DIR/backups"
    BACKUP_FILE=""
    if [ -f "$DB_PATH" ]; then
        mkdir -p "$BACKUP_DIR"
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        BACKUP_FILE="$BACKUP_DIR/vextunnel_${TIMESTAMP}.db"
        
        python3 -c "
import sqlite3
with sqlite3.connect('$DB_PATH', timeout=10.0) as src:
    src.execute('PRAGMA wal_checkpoint(FULL);')
    with sqlite3.connect('$BACKUP_FILE') as dst:
        src.backup(dst)
" || {
            echo -e "${RED}[ERROR] Native SQLite backup failed! Restarting services and aborting.${NC}"
            for svc in "${ACTIVE_SERVICES[@]}"; do
                systemctl start "$svc" 2>/dev/null || true
            done
            exit 1
        }
        echo -e "${GREEN}  ✓ SQLite native backup secured: $(basename "$BACKUP_FILE")${NC}"
    fi

    # Staging download and syntax validation
    STAGING_DIR="/tmp/vextunnel_staging_$$"
    rm -rf "$STAGING_DIR"
    mkdir -p "$STAGING_DIR"
    TAR_TMP="/tmp/vextunnel_dl_$$.tar.gz"

    if [ "$IS_DEV" = "true" ]; then
        curl -sSL -f -o "$TAR_TMP" "https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/main.tar.gz"
    else
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
    fi

    # Extract into isolated staging
    tar -xzf "$TAR_TMP" -C "$STAGING_DIR"
    rm -f "$TAR_TMP"

    # Handle nested folder from GitHub archives
    SRC_DIR="$STAGING_DIR"
    if [ ! -f "$STAGING_DIR/VERSION" ]; then
        NESTED=$(find "$STAGING_DIR" -mindepth 1 -maxdepth 1 -type d | head -1 || true)
        [ -n "$NESTED" ] && [ -f "$NESTED/VERSION" ] && SRC_DIR="$NESTED"
    fi

    # Staging integrity check & syntax verification
    python3 -c "
import os, sys, py_compile
scan_dir = '$SRC_DIR'
required = ['VERSION', 'core/ws_proxy.py', 'core/user_manager.py', 'core/updater.py', 'cli/menu.py']
for req in required:
    p = os.path.join(scan_dir, req)
    if not os.path.isfile(p):
        print(f'Missing critical file: {req}', file=sys.stderr)
        sys.exit(1)

for root, _, files in os.walk(scan_dir):
    for f in files:
        if f.endswith('.py'):
            py_compile.compile(os.path.join(root, f), doraise=True)
" || {
        echo -e "${RED}[ABORT] Staging integrity or Python syntax verification failed!${NC}"
        rm -rf "$STAGING_DIR"
        for svc in "${ACTIVE_SERVICES[@]}"; do
            systemctl start "$svc" 2>/dev/null || true
        done
        exit 1
    }
    echo -e "${GREEN}  ✓ Staging package validated and syntax verified (py_compile OK)${NC}"

    # Phase 2: Codebase Snapshot & Atomic Promotion
    echo -e "${GREEN}==> [2/5] Creating rollback snapshot & promoting codebase...${NC}"
    # Create code rollback snapshot
    tar --exclude='./*.db*' \
        --exclude='./backups' \
        --exclude='./certs' \
        --exclude='./ports.env' \
        --exclude='./__pycache__' \
        --exclude='*/*.pyc' \
        -czf "$CODE_SNAPSHOT" -C "$INSTALL_DIR" . 2>/dev/null || true

    # Purge stale pycache before copy
    find "$INSTALL_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$INSTALL_DIR" -type f -name "*.pyc" -delete 2>/dev/null || true

    # Promote files using rsync/cp with shields
    python3 -c "
import os, shutil
src = '$SRC_DIR'
dst = '$INSTALL_DIR'
protected = {'vextunnel.db', 'vextunnel.db-wal', 'vextunnel.db-shm', 'ports.env', 'domain.conf', 'telegram.json', 'certs', 'backups'}

for root, dirs, files in os.walk(src):
    rel = os.path.relpath(root, src)
    target_d = dst if rel == '.' else os.path.join(dst, rel)
    top = rel.split(os.sep)[0] if rel != '.' else ''
    if top in ('certs', 'backups', '.git'):
        continue
    os.makedirs(target_d, exist_ok=True)
    for f in files:
        if f in protected and os.path.exists(os.path.join(target_d, f)):
            continue
        if f.startswith('vextunnel.db'):
            continue
        shutil.copy2(os.path.join(root, f), os.path.join(target_d, f))
"
    rm -rf "$STAGING_DIR"
    find "$INSTALL_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    chmod +x "$INSTALL_DIR"/install/*.sh "$INSTALL_DIR"/cli/menu.py "$INSTALL_DIR"/core/*.py 2>/dev/null || true
    [ -n "$TARGET_VERSION" ] && [ "$IS_DEV" != "true" ] && echo "$TARGET_VERSION" > "$INSTALL_DIR/VERSION"
    echo -e "${GREEN}  ✓ Codebase promoted safely (Protected shields maintained)${NC}"

    # Phase 3: Systemd Units & Dependencies
    echo -e "${GREEN}==> [3/5] Syncing systemd unit templates & dependencies...${NC}"
    if [ -d "$INSTALL_DIR/install/systemd" ]; then
        cp "$INSTALL_DIR/install/systemd"/vextunnel-*.service /etc/systemd/system/ 2>/dev/null || true
        cp "$INSTALL_DIR/install/systemd"/badvpn-*.service /etc/systemd/system/ 2>/dev/null || true
        systemctl daemon-reload
    fi

    if [ -f "$INSTALL_DIR/requirements.txt" ]; then
        python3 -m pip install -q --no-cache-dir -r "$INSTALL_DIR/requirements.txt" --break-system-packages 2>/dev/null || \
        python3 -m pip install -q --no-cache-dir -r "$INSTALL_DIR/requirements.txt" 2>/dev/null || true
    fi

    # Phase 4: Database Schema Migrations
    echo -e "${GREEN}==> [4/5] Executing database schema migrations...${NC}"
    python3 -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
from core.user_manager import UserManager
UserManager('$DB_PATH')
print('  ✓ Database migrations verified OK')
"

    # Phase 5: Clean Cold Start & Deep Socket Health Check
    echo -e "${GREEN}==> [5/5] Clean cold start of services & deep socket health probing...${NC}"
    systemctl daemon-reload
    for svc in "${ACTIVE_SERVICES[@]}"; do
        systemctl start "$svc" 2>/dev/null || true
    done
    systemctl start vextunnel-enforcer 2>/dev/null || true

    sleep 3 # Settling delay

    # Service & Socket Health Verification
    HEALTH_FAIL=false
    FAILED_SVCS=()
    for svc in vextunnel-ws vextunnel-enforcer dropbear; do
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            FAILED_SVCS+=("$svc")
            HEALTH_FAIL=true
        fi
    done

    # Probe TCP sockets 80 and 109
    SOCKET_FAIL=false
    python3 -c "
import socket, sys
for port in [80, 109]:
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3.0):
            pass
    except Exception as e:
        print(f'Port {port} socket check failed: {e}', file=sys.stderr)
        sys.exit(1)
" || SOCKET_FAIL=true

    if [ "$HEALTH_FAIL" = "true" ] || [ "$SOCKET_FAIL" = "true" ]; then
        echo -e "\n${RED}[CRITICAL ALERT] Health check failed! Services down: ${FAILED_SVCS[*]-none}, Sockets failed: $SOCKET_FAIL${NC}"
        echo -e "${YELLOW}Initiating Two-Tier safe rollback (Codebase + Database)...${NC}"
        
        # Stop services to release locks
        for svc in "${ACTIVE_SERVICES[@]}"; do
            systemctl stop "$svc" 2>/dev/null || true
        done

        # 1. Restore Codebase
        if [ -f "$CODE_SNAPSHOT" ]; then
            tar -xzf "$CODE_SNAPSHOT" -C "$INSTALL_DIR" 2>/dev/null || true
        fi

        # 2. Restore Database
        if [ -f "$BACKUP_FILE" ]; then
            python3 -c "
import sqlite3
with sqlite3.connect('$BACKUP_FILE') as bkp:
    with sqlite3.connect('$DB_PATH') as target:
        bkp.backup(target)
        target.execute('PRAGMA wal_checkpoint(TRUNCATE);')
"
        fi

        # 3. Restart previous stable services
        systemctl daemon-reload
        for svc in "${ACTIVE_SERVICES[@]}"; do
            systemctl restart "$svc" 2>/dev/null || true
        done

        echo -e "${GREEN}✅ Server safely restored to previous stable state from snapshot and backup!${NC}"
        exit 1
    fi

    # Cleanup snapshot upon success
    rm -f "$CODE_SNAPSHOT"

    echo -e "\n${GREEN}${BOLD}==============================================================${NC}"
    echo -e "${GREEN}${BOLD}     ✅ VEXTUNNEL SUCCESSFULLY UPDATED & RUNNING HEALTHY!     ${NC}"
    echo -e "${GREEN}${BOLD}==============================================================${NC}"
}
main "$@"
exit $?
}
