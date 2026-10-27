#!/bin/bash
# ==========================================================
# VexTunnel - Clean BadVPN-UDPGW Builder & Service Setup
# Author: VexElvn
# ==========================================================
set -euo pipefail

echo "==> Setting up BadVPN UDP Gateway for Gaming & VoIP..."

# Install build dependencies
apt-get update -y
apt-get install -y cmake build-essential git

# Build badvpn-udpgw from official source if not present
if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
    echo "==> Building badvpn-udpgw from official source (ambrop72/badvpn)..."
    TMPDIR=$(mktemp -d)
    cd "$TMPDIR"
    curl -sL https://github.com/ambrop72/badvpn/archive/refs/heads/master.tar.gz | tar -xz
    cd badvpn-master
    mkdir build
    cd build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make -j$(nproc)
    cp udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw
    chmod 755 /usr/local/bin/badvpn-udpgw
    cd /
    rm -rf "$TMPDIR"
fi

# Create Systemd Services for Ports 7100, 7200, 7300
for PORT in 7100 7200 7300; do
cat <<EOF > /etc/systemd/system/badvpn-${PORT}.service
[Unit]
Description=BadVPN UDP Gateway on Port ${PORT}
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:${PORT} --max-clients 500 --max-connections-for-client 20
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
systemctl enable badvpn-${PORT}
systemctl restart badvpn-${PORT}
done

echo "==> BadVPN UDPGW active on Ports 7100, 7200, 7300!"
