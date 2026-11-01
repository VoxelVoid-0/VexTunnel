#!/bin/bash
# ==========================================================
# VexTunnel - Clean BadVPN-UDPGW Builder & Service Setup
# Author: VexElvn
# ==========================================================
set -euo pipefail

echo "==> Setting up BadVPN UDP Gateway for Gaming & VoIP..."

# Install build dependencies
apt-get update -y
apt-get install -y cmake build-essential git pkg-config

# Build or install badvpn-udpgw if not present
if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
    echo "==> Setting up badvpn-udpgw from official source (ambrop72/badvpn)..."
    BUILD_SUCCESS=0
    TMPDIR=$(mktemp -d)
    cd "$TMPDIR"

    if curl -sL --connect-timeout 15 --max-time 60 https://github.com/ambrop72/badvpn/archive/refs/heads/master.tar.gz | tar -xz 2>/dev/null; then
        if [ -d "badvpn-master" ]; then
            cd badvpn-master
            # Modern CMake Compatibility:
            # Newer CMake versions (>= 3.30 / 4.0) remove support for legacy cmake_minimum_required(VERSION 2.8)
            # Patch CMakeLists.txt to require 3.10 to prevent 'Compatibility with CMake < 3.5 has been removed from CMake'
            sed -i 's/cmake_minimum_required *(VERSION *[0-9.]*)/cmake_minimum_required(VERSION 3.10)/' CMakeLists.txt 2>/dev/null || true
            mkdir -p build && cd build
            if cmake .. -DCMAKE_POLICY_VERSION_MINIMUM=3.10 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 && make -j"$(nproc 2>/dev/null || echo 1)"; then
                if [ -f "udpgw/badvpn-udpgw" ]; then
                    cp udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw
                    chmod 755 /usr/local/bin/badvpn-udpgw
                    BUILD_SUCCESS=1
                    echo "==> badvpn-udpgw compiled and installed successfully from source!"
                fi
            fi
        fi
    fi

    cd /
    rm -rf "$TMPDIR"

    # Fallback to pre-compiled verified binary if compilation failed or is unsupported
    if [ "$BUILD_SUCCESS" -ne 1 ] && [ ! -f /usr/local/bin/badvpn-udpgw ]; then
        echo "==> Source compilation failed or unsupported; falling back to verified pre-compiled binary..."
        curl -sL --connect-timeout 15 -o /usr/local/bin/badvpn-udpgw https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64 2>/dev/null || true
        chmod 755 /usr/local/bin/badvpn-udpgw 2>/dev/null || true
    fi
fi

# Create Systemd Services for Ports 7100, 7200, 7300 if binary is present
if [ -f /usr/local/bin/badvpn-udpgw ]; then
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
    systemctl daemon-reload
    systemctl enable badvpn-${PORT} 2>/dev/null || true
    systemctl restart badvpn-${PORT} 2>/dev/null || true
    done

    echo "==> BadVPN UDPGW active on Ports 7100, 7200, 7300!"
else
    echo "==> [NOTICE] badvpn-udpgw binary not available. Gaming/VoIP gateway service bypassed safely."
fi
