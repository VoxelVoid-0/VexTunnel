#!/bin/bash
# ==========================================================
# VexTunnel - WebSocket Proxy Systemd Setup
# Author: VoxelVoid-0
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
    cp "$DIR/core/quota_manager.py" /etc/vextunnel/core/
    cp "$DIR/core/ports_manager.py" /etc/vextunnel/core/ 2>/dev/null || true
    cp "$DIR/core/monitor.py" /etc/vextunnel/core/
    cp "$DIR/core/updater.py" /etc/vextunnel/core/ 2>/dev/null || true
    cp "$DIR/cli/menu.py" /etc/vextunnel/cli/
fi

# Ensure default ports.env exists without clobbering user overrides
if [ ! -f /etc/vextunnel/ports.env ]; then
    if [ -f "$DIR/core/ports.env" ]; then
        cp "$DIR/core/ports.env" /etc/vextunnel/ports.env
    else
        cat <<'EOF' > /etc/vextunnel/ports.env
WS_PORT=80
WSS_PORT=443
WS_ALT_PORT=8880
DROPBEAR_PORT=109
BADVPN_PORT=7300
WSS_ENABLED=true
EOF
    fi
fi

chmod +x /etc/vextunnel/core/ws_proxy.py
chmod +x /etc/vextunnel/core/session_enforcer.py
chmod +x /etc/vextunnel/core/quota_manager.py
chmod +x /etc/vextunnel/core/ports_manager.py 2>/dev/null || true
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

# Deploy systemd units from templates if available
if [ -d "$DIR/install/systemd" ]; then
    cp "$DIR/install/systemd"/vextunnel-*.service /etc/systemd/system/ 2>/dev/null || true
fi

# Create Systemd Service for WebSocket Proxy (Port 80 -> Dropbear 109)
cat <<'EOF' > /etc/systemd/system/vextunnel-ws.service
[Unit]
Description=VexTunnel Async SSH WebSocket Proxy (Port 80)
After=network.target dropbear.service

[Service]
Type=simple
User=root
Environment="WS_PORT=80" "DROPBEAR_PORT=109"
EnvironmentFile=-/etc/vextunnel/ports.env
ExecStart=/usr/bin/python3 /etc/vextunnel/core/ws_proxy.py --listen-port $WS_PORT --target-port $DROPBEAR_PORT --response-code 101
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
Environment="WS_ALT_PORT=8880" "DROPBEAR_PORT=109"
EnvironmentFile=-/etc/vextunnel/ports.env
ExecStart=/usr/bin/python3 /etc/vextunnel/core/ws_proxy.py --listen-port $WS_ALT_PORT --target-port $DROPBEAR_PORT --response-code 101
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
Environment="WSS_PORT=443" "DROPBEAR_PORT=109"
EnvironmentFile=-/etc/vextunnel/ports.env
ExecStart=/usr/bin/python3 /etc/vextunnel/core/ws_proxy.py --listen-port $WSS_PORT --target-port $DROPBEAR_PORT --ssl-cert /etc/vextunnel/certs/cert.pem --ssl-key /etc/vextunnel/certs/key.pem --response-code 101
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

# Check if WSS is enabled or disabled
WSS_ACTIVE=true
if [ -f /etc/vextunnel/ports.env ]; then
    if grep -iq "^WSS_ENABLED=false" /etc/vextunnel/ports.env; then
        WSS_ACTIVE=false
    fi
fi

if [ "$WSS_ACTIVE" = "true" ]; then
    systemctl enable vextunnel-ws vextunnel-wss vextunnel-ws-8880 vextunnel-enforcer
    systemctl restart vextunnel-ws vextunnel-wss vextunnel-ws-8880 vextunnel-enforcer
    echo "==> VexTunnel Services (WS 80, WSS 443, Session Enforcer) active!"
else
    systemctl stop vextunnel-wss 2>/dev/null || true
    systemctl disable vextunnel-wss 2>/dev/null || true
    systemctl enable vextunnel-ws vextunnel-ws-8880 vextunnel-enforcer
    systemctl restart vextunnel-ws vextunnel-ws-8880 vextunnel-enforcer
    echo "==> VexTunnel Services (WS 80, 8880, Session Enforcer) active (WSS Standby for 3x-ui)!"
fi
