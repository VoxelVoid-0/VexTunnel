#!/bin/bash
# ==========================================================
# VexTunnel - Clean OpenSSH & Dropbear Configurator
# Author: VoxelVoid-0
# ==========================================================
set -euo pipefail

echo "==> Configuring SSH & Dropbear Daemons..."

# 1. Install Dropbear
apt-get update -y
apt-get install -y dropbear openssh-server

# 2. Configure OpenSSH Ports (22, 2222)
if ! grep -q "Port 2222" /etc/ssh/sshd_config; then
    sed -i '/^#Port 22/s/^#//' /etc/ssh/sshd_config
    sed -i '/^Port 22/a Port 2222' /etc/ssh/sshd_config
fi
sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true

# Harden OpenSSH session & keepalive limits
sed -i '/^MaxSessions/d' /etc/ssh/sshd_config 2>/dev/null || true
echo "MaxSessions 10" >> /etc/ssh/sshd_config
sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config 2>/dev/null || true
echo "ClientAliveInterval 120" >> /etc/ssh/sshd_config
sed -i '/^ClientAliveCountMax/d' /etc/ssh/sshd_config 2>/dev/null || true
echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config

# Configure security limits for multi-session control
if [ -f /etc/security/limits.conf ] && ! grep -q "maxlogins" /etc/security/limits.conf; then
    echo "* hard maxlogins 4" >> /etc/security/limits.conf
fi

# Reload systemd and restart SSH service and socket (for Ubuntu 22.04+ socket activation)
systemctl daemon-reload 2>/dev/null || true
if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    systemctl restart ssh.socket 2>/dev/null || true
fi
systemctl restart ssh 2>/dev/null || true

# 3. Configure Dropbear Ports (Hybrid: Systemd Drop-in + SysV fallback)
DROPBEAR_CFG_PORT=109
DROPBEAR_CFG_ALT=143
if [ -f /etc/vextunnel/ports.env ]; then
    DROPBEAR_CFG_PORT=$(grep "^DROPBEAR_PORT=" /etc/vextunnel/ports.env | cut -d= -f2 || echo 109)
    DROPBEAR_CFG_ALT=$(grep "^DROPBEAR_ALT_PORT=" /etc/vextunnel/ports.env | cut -d= -f2 || echo 143)
fi

# Pre-flight deconfliction: stop potential crashing instances and socket units
systemctl stop dropbear 2>/dev/null || true
systemctl disable --now dropbear.socket 2>/dev/null || true
systemctl reset-failed dropbear 2>/dev/null || true

# Ensure host keys directory exists and generate RSA/ECDSA/ED25519 if missing
mkdir -p /etc/dropbear
[ -f /etc/dropbear/dropbear_rsa_host_key ] || dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key 2>/dev/null || true
[ -f /etc/dropbear/dropbear_ecdsa_host_key ] || dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key 2>/dev/null || true
[ -f /etc/dropbear/dropbear_ed25519_host_key ] || dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null || true
chmod 600 /etc/dropbear/*_key 2>/dev/null || true

# Tier 1: Modern Systemd Drop-in Override (bypasses port 22 binding cleanly across Ubuntu 24.04+/26.04)
mkdir -p /etc/systemd/system/dropbear.service.d
cat <<EOF > /etc/systemd/system/dropbear.service.d/override.conf
[Unit]
Description=Lightweight SSH server (VexTunnel Hardened)
After=network.target

[Service]
EnvironmentFile=-/etc/default/dropbear
ExecStart=
ExecStart=/usr/sbin/dropbear -EF -R -p ${DROPBEAR_CFG_ALT} -p ${DROPBEAR_CFG_PORT} -W 65536
Restart=always
RestartSec=3
EOF

# Tier 2: SysV /etc/default/dropbear fallback for older Debian/Ubuntu distributions
cat <<EOF > /etc/default/dropbear
NO_START=0
DROPBEAR_PORT=${DROPBEAR_CFG_ALT}
DROPBEAR_EXTRA_ARGS="-R -p ${DROPBEAR_CFG_PORT}"
DROPBEAR_BANNER=""
DROPBEAR_RECEIVE_WINDOW=65536
EOF

# Ensure restricted shells exist
grep -qxF "/bin/false" /etc/shells || echo "/bin/false" >> /etc/shells
grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >> /etc/shells

systemctl daemon-reload
systemctl reset-failed dropbear 2>/dev/null || true
systemctl enable dropbear
systemctl restart dropbear

echo "==> OpenSSH (Ports 22, 2222) and Dropbear (Ports ${DROPBEAR_CFG_PORT}, ${DROPBEAR_CFG_ALT}) are active!"
