#!/bin/bash
# ==========================================================
# VexTunnel - Safe Automated Account Expiry Service
# Author: VexElvn
# ==========================================================
set -euo pipefail

echo "==> Configuring Safe Account Expiration Timer..."

# Stop and disable old services if present
systemctl stop securetunnel-expiry.timer securetunnel-expiry.service 2>/dev/null || true
systemctl disable securetunnel-expiry.timer securetunnel-expiry.service 2>/dev/null || true

# Create systemd service for running cleanup
cat <<'EOF' > /etc/systemd/system/vextunnel-expiry.service
[Unit]
Description=VexTunnel Daily User Expiry Cleanup
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /etc/vextunnel/core/user_manager.py cleanup
EOF

# Create daily timer (Runs every day at 00:00)
cat <<'EOF' > /etc/systemd/system/vextunnel-expiry.timer
[Unit]
Description=Daily Timer for VexTunnel User Expiry Check

[Timer]
OnCalendar=*-*-* 00:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable vextunnel-expiry.timer
systemctl start vextunnel-expiry.timer

echo "==> Automated Account Expiry timer enabled safely!"
