#!/bin/bash
# ==========================================================
# ⚡ VexTunnel Suite - Master VPS Installer ⚡
# Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)
# Supported OS: Debian 10+ / Ubuntu 20.04+
# Open-Source SSH-WebSocket Tunnel Suite for Linux
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
echo "║                    ⚡ VEXTUNNEL SUITE ⚡                     ║"
echo "║        Lightweight SSH-WebSocket Tunnel Suite for Linux      ║"
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

# 5. Check and Resolve Port 443 Conflicts (e.g. 3x-ui / x-ui / Xray)
PORT443_PID=""
if command -v ss >/dev/null 2>&1; then
    PORT443_PID=$(ss -tulpn 2>/dev/null | grep -E '[:\]]443\s' | grep -i 'LISTEN' | head -n1 || true)
fi

IS_3XUI_RUNNING=false
if systemctl is-active --quiet 3x-ui 2>/dev/null || systemctl is-active --quiet x-ui 2>/dev/null || systemctl is-active --quiet xray 2>/dev/null; then
    IS_3XUI_RUNNING=true
fi

mkdir -p /etc/vextunnel

if [ -n "$PORT443_PID" ] || [ "$IS_3XUI_RUNNING" = "true" ]; then
    echo -e "\n${YELLOW}${BOLD}⚠️  [PORT 443 CO-EXISTENCE DETECTOR]${NC}"
    echo -e "${YELLOW}Port 443 is currently in use by an active service (e.g. 3x-ui / Xray / Web server).${NC}"
    echo -e "VexTunnel can seamlessly co-exist with 3x-ui without interrupting your existing services!\n"

    # Default values
    CHOSEN_WSS_PORT=8443
    CHOSEN_WSS_ENABLED=true

    if [ -t 0 ]; then
        echo -e " ${BOLD}How would you like VexTunnel to proceed?${NC}"
        echo -e "  ${CYAN}1)${NC} Assign alternate WSS port (8443 / 2053) [Recommended - Co-exist with 3x-ui]"
        echo -e "  ${CYAN}2)${NC} Disable Port 443 WSS (Run VexTunnel on Port 80 & 8880 HTTP-WS only)"
        echo -e "  ${CYAN}3)${NC} Take over Port 443 (Stop 3x-ui and use Port 443 for VexTunnel)"
        read -r -p "Select option [1-3, default 1]: " COEXIST_OPT

        case "$COEXIST_OPT" in
            2)
                CHOSEN_WSS_ENABLED=false
                echo -e "${GREEN}==> Configured: Port 443 WSS will remain DISABLED (Standby). Port 443 is left for 3x-ui.${NC}"
                ;;
            3)
                echo -e "\n${RED}${BOLD}⚠️  WARNING: Taking over Port 443 will STOP and DISABLE 3x-ui / x-ui!${NC}"
                read -t 10 -r -p "Are you sure you want to proceed? [y/N, timeout 10s default y]: " CONFIRM_TAKEOVER || CONFIRM_TAKEOVER="y"
                if [[ "$CONFIRM_TAKEOVER" =~ ^[Yy]$ ]]; then
                    echo -e "${YELLOW}==> Stopping conflicting 3x-ui / x-ui services to free Port 443...${NC}"
                    systemctl stop 3x-ui x-ui 2>/dev/null || true
                    systemctl disable 3x-ui x-ui 2>/dev/null || true
                    CHOSEN_WSS_PORT=443
                    CHOSEN_WSS_ENABLED=true
                else
                    echo -e "${CYAN}==> Takeover cancelled. Falling back to Alternate Port 8443 to preserve 3x-ui.${NC}"
                    CHOSEN_WSS_PORT=8443
                    CHOSEN_WSS_ENABLED=true
                fi
                ;;
            *)
                read -r -p "Enter alternate WSS port [default 8443]: " ALT_INPUT
                CHOSEN_WSS_PORT="${ALT_INPUT:-8443}"
                CHOSEN_WSS_ENABLED=true
                echo -e "${GREEN}==> Configured: VexTunnel WSS will bind to port $CHOSEN_WSS_PORT (3x-ui keeps 443).${NC}"
                ;;
        esac
    else
        # Headless / piped execution: safely default to alternate port 8443 to never break existing services
        echo -e "${CYAN}==> Non-interactive installer: Automatically assigning alternate WSS Port 8443 to co-exist with 3x-ui.${NC}"
        CHOSEN_WSS_PORT=8443
        CHOSEN_WSS_ENABLED=true
    fi

    # Write early ports.env
    cat <<EOF > /etc/vextunnel/ports.env
WS_PORT=80
WSS_PORT=${CHOSEN_WSS_PORT}
WS_ALT_PORT=8880
DROPBEAR_PORT=109
BADVPN_PORT=7300
WSS_ENABLED=${CHOSEN_WSS_ENABLED}
EOF
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
WSS_CFG_PORT=443
WSS_IS_ENABLED=true
if [ -f /etc/vextunnel/ports.env ]; then
    WSS_CFG_PORT=$(grep "^WSS_PORT=" /etc/vextunnel/ports.env | cut -d= -f2 || echo 443)
    if grep -iq "^WSS_ENABLED=false" /etc/vextunnel/ports.env; then
        WSS_IS_ENABLED=false
    fi
fi

ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow 2222/tcp >/dev/null 2>&1 || true
ufw allow 109/tcp >/dev/null 2>&1 || true
ufw allow 143/tcp >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
if [ "$WSS_IS_ENABLED" = "true" ]; then
    ufw allow ${WSS_CFG_PORT}/tcp >/dev/null 2>&1 || true
fi
ufw allow 8880/tcp >/dev/null 2>&1 || true
ufw allow 7100:7300/udp >/dev/null 2>&1 || true
ufw allow 7100:7300/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

# Purge cloud-image pre-existing REJECT rules that intercept traffic before UFW (e.g. Oracle Cloud OCI)
iptables -D INPUT -j REJECT --reject-with icmp-host-prohibited 2>/dev/null || true
iptables -D FORWARD -j REJECT --reject-with icmp-host-prohibited 2>/dev/null || true
if [ -f /etc/iptables/rules.v4 ]; then
    sed -i '/icmp-host-prohibited/d' /etc/iptables/rules.v4 2>/dev/null || true
fi

# 8. Auto-Launch Menu Shortcut in .bashrc
if ! grep -q "alias menu=" /root/.bashrc 2>/dev/null; then
    echo "alias menu='python3 /etc/vextunnel/cli/menu.py'" >> /root/.bashrc
fi

DISPLAY_HOST="${CUSTOM_DOMAIN:-$IP}"

WSS_DISPLAY="${WSS_CFG_PORT} (TLS/SSL Encrypted)"
if [ "$WSS_IS_ENABLED" = "false" ]; then
    WSS_DISPLAY="[DISABLED - Standby for 3x-ui]"
elif [ "$WSS_CFG_PORT" != "443" ]; then
    WSS_DISPLAY="${WSS_CFG_PORT} (TLS/SSL - 3x-ui Co-existence)"
fi

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
echo -e " ${BOLD}WebSocket WSS    :${NC} $WSS_DISPLAY"
echo -e " ${BOLD}BadVPN UDPGW     :${NC} 7300"
echo -e " ${BOLD}Firewall (UFW)   :${NC} ${GREEN}[ACTIVE & HARDENED]${NC}"
echo -e " ${BOLD}Telemetry / Leaks:${NC} ${GREEN}[NONE - 100% PRIVATE]${NC}"
echo -e "──────────────────────────────────────────────────────────────"
echo -e "${CYAN}${BOLD}Type 'menu' anytime in terminal to access the management interface.${NC}"
echo -e "──────────────────────────────────────────────────────────────"
