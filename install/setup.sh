#!/bin/bash
# ==========================================================
# ⚡ VexTunnel Suite - Master VPS Installer ⚡
# Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)
# Supported OS: Debian 10+ / Ubuntu 20.04+
# 100% Open-Source • Zero-Backdoor • Clean Production Ready
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

# 1. Check Root
if [ "${EUID}" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installation script must be run as root!${NC}"
    exit 1
fi

# 2. Check Architecture
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
echo -e "${GREEN}==> Detected Architecture: ${CYAN}${BOLD}${ARCH_TYPE}${NC}"

# 3. Get Public IP
IP=$(curl -s https://api.ipify.org || curl -s ifconfig.me || echo "127.0.0.1")

# 4. Host Configuration Wizard (IP vs Domain)
CUSTOM_DOMAIN=""
if [ -t 0 ]; then
    echo -e "\n${BOLD}[ HOST CONFIGURATION ]${NC}"
    echo -e "  ${CYAN}1)${NC} Direct Server IP (${YELLOW}${IP}${NC}) [Recommended - Instant Setup]"
    echo -e "  ${CYAN}2)${NC} Custom Domain (For Sellers / Resellers / Cloudflare)"
    read -r -p "Select option [1-2, default 1]: " HOST_OPT
    if [ "$HOST_OPT" = "2" ]; then
        read -r -p "Enter your custom domain (e.g. vpn.example.com): " USER_INPUT_DOMAIN
        CUSTOM_DOMAIN=$(echo "$USER_INPUT_DOMAIN" | tr -d '[:space:]')
    fi
fi

# 5. Check and Resolve Port 443 Conflicts (e.g. x-ui)
if systemctl is-active --quiet x-ui 2>/dev/null; then
    echo -e "${YELLOW}==> Detected x-ui running on Port 443. Stopping and disabling x-ui to free Port 443 for VexTunnel WSS...${NC}"
    systemctl stop x-ui 2>/dev/null || true
    systemctl disable x-ui 2>/dev/null || true
fi

echo -e "${GREEN}==> Updating base system and installing dependencies...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
    curl wget python3 sqlite3 ufw jq unzip tar net-tools openssl \
    build-essential cmake git openssh-server dropbear

# 6. Run Modular Component Installers
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\n${CYAN}==> [1/5] Configuring SSH & Dropbear...${NC}"
bash "$DIR/install_ssh.sh"

echo -e "\n${CYAN}==> [2/5] Configuring SSL/TLS Certificates...${NC}"
if [ -n "$CUSTOM_DOMAIN" ]; then
    bash "$DIR/install_ssl.sh" --domain "$CUSTOM_DOMAIN"
else
    bash "$DIR/install_ssl.sh" --self-signed
fi

echo -e "\n${CYAN}==> [3/5] Setting up Async SSH WebSocket Proxies (Ports 80 & 443)...${NC}"
bash "$DIR/install_ws.sh"

echo -e "\n${CYAN}==> [4/5] Building & Configuring BadVPN UDPGW (Gaming/VoIP)...${NC}"
bash "$DIR/install_badvpn.sh"

echo -e "\n${CYAN}==> [5/5] Setting up Safe User Expiration Timer...${NC}"
bash "$DIR/install_cron.sh"

# 7. Configure Firewall (UFW)
echo -e "\n${GREEN}==> Updating Firewall (UFW) rules without touching existing configs...${NC}"
ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow 2222/tcp >/dev/null 2>&1 || true
ufw allow 109/tcp >/dev/null 2>&1 || true
ufw allow 143/tcp >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw allow 8880/tcp >/dev/null 2>&1 || true
ufw allow 7100:7300/udp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

# 8. Auto-Launch Menu Shortcut in .bashrc
if ! grep -q "alias menu=" /root/.bashrc 2>/dev/null; then
    echo "alias menu='python3 /etc/vextunnel/cli/menu.py'" >> /root/.bashrc
fi

DISPLAY_HOST="${CUSTOM_DOMAIN:-$IP}"

clear 2>/dev/null || true
echo -e "${GREEN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           ✅ VEXTUNNEL SUITE INSTALLED SUCCESSFULLY!         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e " ${BOLD}Host / Domain    :${NC} ${YELLOW}$DISPLAY_HOST${NC}"
echo -e " ${BOLD}Server Public IP :${NC} ${YELLOW}$IP${NC}"
echo -e " ${BOLD}OpenSSH Ports    :${NC} 22, 2222"
echo -e " ${BOLD}Dropbear Ports   :${NC} 109, 143"
echo -e " ${BOLD}WebSocket HTTP   :${NC} 80, 8880"
echo -e " ${BOLD}WebSocket WSS    :${NC} 443 (TLS/SSL Encrypted)"
echo -e " ${BOLD}BadVPN UDPGW     :${NC} 7300"
echo -e " ${BOLD}Firewall (UFW)   :${NC} ${GREEN}[ACTIVE & HARDENED]${NC}"
echo -e " ${BOLD}Telemetry / Leaks:${NC} ${GREEN}[NONE - 100% PRIVATE]${NC}"
echo -e "──────────────────────────────────────────────────────────────"
echo -e "${CYAN}${BOLD}Type 'menu' anytime in terminal to launch the management hub!${NC}"
echo -e "──────────────────────────────────────────────────────────────"
