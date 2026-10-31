#!/bin/bash
# ==========================================================
# ⚡ VexTunnel - SSL / TLS Certificate Automation ⚡
# Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)
# License: MIT
# ==========================================================
set -euo pipefail

# Visual Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

CERTS_DIR="/etc/vextunnel/certs"
mkdir -p "$CERTS_DIR"

SERVER_IP=$(curl -s https://api.ipify.org || curl -s ifconfig.me || echo "127.0.0.1")
MODE="${1:---self-signed}"
DOMAIN="${2:-}"

generate_self_signed() {
    local target_cn="${1:-$SERVER_IP}"
    echo -e "${CYAN}==> Generating 2048-bit RSA Self-Signed SSL Certificate for [${target_cn}]...${NC}"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$CERTS_DIR/key.pem" \
        -out "$CERTS_DIR/cert.pem" \
        -subj "/C=US/ST=State/L=City/O=VexTunnel/CN=$target_cn" >/dev/null 2>&1
    chmod 600 "$CERTS_DIR/key.pem"
    chmod 644 "$CERTS_DIR/cert.pem"
    echo -e "${GREEN}==> Self-Signed SSL Certificate successfully created at $CERTS_DIR/cert.pem!${NC}"
}

if [ "$MODE" = "--domain" ] && [ -n "$DOMAIN" ]; then
    echo -e "${CYAN}==> Setting up SSL Certificate for custom domain: ${YELLOW}$DOMAIN${NC}"
    # Save configured domain
    echo "$DOMAIN" > /etc/vextunnel/domain.conf

    # Check if certbot is installed
    if ! command -v certbot >/dev/null 2>&1; then
        echo -e "${YELLOW}==> Installing certbot for Let's Encrypt automated SSL...${NC}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y certbot >/dev/null 2>&1 || true
    fi

    # Attempt to obtain official certificate
    echo -e "${CYAN}==> Requesting Let's Encrypt SSL certificate...${NC}"
    if certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email >/dev/null 2>&1; then
        cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERTS_DIR/cert.pem"
        cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERTS_DIR/key.pem"
        chmod 600 "$CERTS_DIR/key.pem"
        chmod 644 "$CERTS_DIR/cert.pem"
        echo -e "${GREEN}==> Official Let's Encrypt SSL certificate installed successfully!${NC}"
    else
        echo -e "${YELLOW}[WARNING] Let's Encrypt verification failed (DNS A Record may not have fully propagated yet).${NC}"
        echo -e "${YELLOW}==> Generating High-Security Self-Signed SSL certificate for $DOMAIN as fallback...${NC}"
        generate_self_signed "$DOMAIN"
    fi
else
    # Direct IP Mode
    generate_self_signed "$SERVER_IP"
fi
