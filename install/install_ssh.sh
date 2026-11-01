#!/bin/bash
# ==========================================================
# VexTunnel - Clean OpenSSH & Dropbear Configurator
# Author: VexElvn
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
echo "MaxSessions 2" >> /etc/ssh/sshd_config
sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config 2>/dev/null || true
echo "ClientAliveInterval 120" >> /etc/ssh/sshd_config
sed -i '/^ClientAliveCountMax/d' /etc/ssh/sshd_config 2>/dev/null || true
echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config

# Configure security limits for multi-session control
if [ -f /etc/security/limits.conf ] && ! grep -q "maxlogins" /etc/security/limits.conf; then
    echo "* hard maxlogins 4" >> /etc/security/limits.conf
fi

systemctl restart ssh

# 3. Configure Dropbear Ports (109, 143)
cat <<'EOF' > /etc/default/dropbear
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 109"
DROPBEAR_BANNER=""
DROPBEAR_RECEIVE_WINDOW=65536
EOF

# Ensure restricted shells exist
grep -qxF "/bin/false" /etc/shells || echo "/bin/false" >> /etc/shells
grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >> /etc/shells

systemctl enable dropbear
systemctl restart dropbear

echo "==> OpenSSH (Ports 22, 2222) and Dropbear (Ports 109, 143) are active!"
