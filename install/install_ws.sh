#!/bin/bash
# ==========================================================
# VexTunnel - WebSocket Proxy Systemd Setup
# Author: VexElvn
# ==========================================================
set -euo pipefail

echo "==> Setting up VexTunnel Async WebSocket Proxy..."

# Determine project base directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Create app directory
mkdir -p /etc/vextunnel/core
mkdir -p /etc/vextunnel/cli

# Copy core files if not already in /etc/vextunnel
if [ "$DIR" != "/etc/vextunnel" ]; then
    cp "$DIR/core/ws_proxy.py" /etc/vextunnel/core/
    cp "$DIR/core/user_manager.py" /etc/vextunnel/core/
    cp "$DIR/core/session_enforcer.py" /etc/vextunnel/core/
    cp "$DIR/core/monitor.py" /etc/vextunnel/core/
    cp "$DIR/cli/menu.py" /etc/vextunnel/cli/
fi

chmod +x /etc/vextunnel/core/ws_proxy.py
chmod +x /etc/vextunnel/core/session_enforcer.py
chmod +x /etc/vextunnel/cli/menu.py

# Create global 'menu' command
cat <<'EOF' > /usr/local/bin/menu
#!/bin/bash
exec python3 /etc/vextunnel/cli/menu.py "$@"
EOF
chmod +x /usr/local/bin/menu

# Stop old services if they existed under previous names
systemctl stop securetunnel-ws securetunnel-ws-8880 2>/dev/null || true
systemctl disable securetunnel-ws securetunnel-ws-8880 2>/dev/null || true

# Create Systemd Service for WebSocket Proxy (Port 80 -> Dropbear 109)
cat <<'EOF' > /etc/systemd/system/vextunnel-ws.service
[Unit]
Description=VexTunnel Async SSH WebSocket Proxy (Port 80)
After=network.target dropbear.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /etc/vextunnel/core/ws_proxy.py --listen-port 80 --target-port 109 --response-code 101
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Create Secondary Port 8880 Service (HTTP Alternate)
cat <<'EOF' > /etc/systemd/system/vextunnel-ws-8880.service
[Unit]
Description=VexTunnel Async SSH WebSocket Proxy (Port 8880)
After=network.target dropbear.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /etc/vextunnel/core/ws_proxy.py --listen-port 8880 --target-port 109 --response-code 101
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Create Port 443 TLS/WSS Service (Encrypted WebSocket)
cat <<'EOF' > /etc/systemd/system/vextunnel-wss.service
[Unit]
Description=VexTunnel Async SSH WebSocket Proxy over TLS (Port 443)
After=network.target dropbear.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /etc/vextunnel/core/ws_proxy.py --listen-port 443 --target-port 109 --ssl-cert /etc/vextunnel/certs/cert.pem --ssl-key /etc/vextunnel/certs/key.pem --response-code 101
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Create Session Concurrency Enforcer Service
cat <<'EOF' > /etc/systemd/system/vextunnel-enforcer.service
[Unit]
Description=VexTunnel Real-Time Session Concurrency & Limit Enforcer
After=network.target dropbear.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /etc/vextunnel/core/session_enforcer.py
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vextunnel-ws vextunnel-wss vextunnel-ws-8880 vextunnel-enforcer
systemctl restart vextunnel-ws vextunnel-wss vextunnel-ws-8880 vextunnel-enforcer

echo "==> VexTunnel Services (WS 80, WSS 443, Session Enforcer) active!"
