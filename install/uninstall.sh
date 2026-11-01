#!/bin/bash
# ==========================================================
# ⚡ VexTunnel Suite - Complete Clean Uninstaller ⚡
# Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)
# ==========================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

if [ "${EUID}" -ne 0 ]; then
    echo -e "${RED}[ERROR] This uninstallation script must be run as root!${NC}"
    exit 1
fi

echo -e "${YELLOW}${BOLD}==> Stopping and disabling all VexTunnel background services...${NC}"
systemctl stop vextunnel-ws vextunnel-wss vextunnel-enforcer vextunnel-expiry.timer vextunnel-quota-reset.timer badvpn-7300 badvpn-7200 badvpn-7100 2>/dev/null || true
systemctl disable vextunnel-ws vextunnel-wss vextunnel-enforcer vextunnel-expiry.timer vextunnel-quota-reset.timer badvpn-7300 badvpn-7200 badvpn-7100 2>/dev/null || true

echo -e "${YELLOW}==> Removing systemd service units...${NC}"
rm -f /etc/systemd/system/vextunnel* /etc/systemd/system/badvpn*
systemctl daemon-reload

echo -e "${YELLOW}==> Removing dedicated VexTunnel firewall chains...${NC}"
iptables -D OUTPUT -j VEXTUNNEL_BLOCK 2>/dev/null || true
iptables -D OUTPUT -j VEXTUNNEL_QUOTA 2>/dev/null || true
iptables -D INPUT -j VEXTUNNEL_LIMIT 2>/dev/null || true
iptables -F VEXTUNNEL_BLOCK 2>/dev/null || true
iptables -X VEXTUNNEL_BLOCK 2>/dev/null || true
iptables -F VEXTUNNEL_QUOTA 2>/dev/null || true
iptables -X VEXTUNNEL_QUOTA 2>/dev/null || true
iptables -F VEXTUNNEL_LIMIT 2>/dev/null || true
iptables -X VEXTUNNEL_LIMIT 2>/dev/null || true

echo -e "${YELLOW}==> Removing cron automation...${NC}"
rm -f /etc/cron.d/vextunnel-cleanup

echo -e "${YELLOW}==> Removing binaries and menu aliases...${NC}"
rm -f /usr/local/bin/badvpn-udpgw /usr/local/bin/vextunnel
sed -i '/alias menu=/d' /root/.bashrc 2>/dev/null || true

echo -e "${YELLOW}==> Removing configuration directory and logs...${NC}"
rm -rf /etc/vextunnel /var/log/vextunnel

echo -e "${GREEN}${BOLD}==========================================================${NC}"
echo -e "${GREEN}${BOLD}  ✅ VexTunnel Suite has been completely and cleanly removed! ${NC}"
echo -e "${GREEN}${BOLD}==========================================================${NC}"
