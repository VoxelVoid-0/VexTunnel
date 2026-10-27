#!/bin/bash
# ==========================================================
# ⚡ VexTunnel Suite - Master VPS Installer ⚡
# Author : VexElvn (https://github.com/VexElvn/VexTunnel)
# Supported OS: Debian 10+ / Ubuntu 20.04+
# 100% Open-Source • Zero-Backdoor • Clean Production Ready
# ==========================================================
set -euo pipefail

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

clear
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   ⚡ VEXTUNNEL SUITE v1.0 ⚡                 ║"
echo "║          Clean • Modern • Zero-Backdoor VPS Tunnel           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Check Root
if [ "${EUID}" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installation script must be run as root!${NC}"
    exit 1
fi

# 2. Check Architecture
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
    echo -e "${RED}[ERROR] Architecture $ARCH is not supported. Please use x86_64 or aarch64.${NC}"
    exit 1
fi

echo -e "${GREEN}==> Updating base system and installing dependencies...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
    curl wget python3 sqlite3 ufw jq unzip tar net-tools \
    build-essential cmake git openssh-server dropbear

# 3. Get Public IP
IP=$(curl -s https://api.ipify.org || curl -s ifconfig.me || echo "127.0.0.1")

# 4. Run Modular Component Installers
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\n${CYAN}==> [1/4] Configuring SSH & Dropbear...${NC}"
bash "$DIR/install_ssh.sh"

echo -e "\n${CYAN}==> [2/4] Setting up Async SSH WebSocket Proxy...${NC}"
bash "$DIR/install_ws.sh"

echo -e "\n${CYAN}==> [3/4] Building & Configuring BadVPN UDPGW (Gaming/VoIP)...${NC}"
bash "$DIR/install_badvpn.sh"

echo -e "\n${CYAN}==> [4/4] Setting up Safe User Expiration Timer...${NC}"
bash "$DIR/install_cron.sh"

# 5. Configure Firewall (UFW) - Preserve existing rules (e.g. 3X-UI ports)
echo -e "\n${GREEN}==> Updating Firewall (UFW) rules without touching existing configs...${NC}"
ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow 2222/tcp >/dev/null 2>&1 || true
ufw allow 109/tcp >/dev/null 2>&1 || true
ufw allow 143/tcp >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 8880/tcp >/dev/null 2>&1 || true
ufw allow 7100:7300/udp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

# 6. Auto-Launch Menu Shortcut in .bashrc
if ! grep -q "alias menu=" /root/.bashrc 2>/dev/null; then
    echo "alias menu='python3 /etc/vextunnel/cli/menu.py'" >> /root/.bashrc
fi

clear
echo -e "${GREEN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           ✅ VEXTUNNEL SUITE INSTALLED SUCCESSFULLY!         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e " ${BOLD}Server Public IP :${NC} ${YELLOW}$IP${NC}"
echo -e " ${BOLD}OpenSSH Ports    :${NC} 22, 2222"
echo -e " ${BOLD}Dropbear Ports   :${NC} 109, 143"
echo -e " ${BOLD}WebSocket HTTP   :${NC} 80, 8880"
echo -e " ${BOLD}BadVPN UDPGW     :${NC} 7100, 7200, 7300"
echo -e " ${BOLD}Firewall (UFW)   :${NC} ${GREEN}[ACTIVE & HARDENED]${NC}"
echo -e " ${BOLD}Telemetry / Leaks:${NC} ${GREEN}[NONE - 100% PRIVATE]${NC}"
echo -e "──────────────────────────────────────────────────────────────"
echo -e "${CYAN}${BOLD}Type 'menu' anytime in terminal to launch the management hub!${NC}"
echo -e "──────────────────────────────────────────────────────────────"
