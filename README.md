# ⚡ VexTunnel

[![VexTunnel CI](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml)
[![Security Analysis](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/VoxelVoid-0/VexTunnel?color=blue&logo=github)](https://github.com/VoxelVoid-0/VexTunnel/releases/latest)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64-orange.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](#)

A fast, lightweight SSH-over-WebSocket proxy and tunneling manager for Linux VPS. Designed for high throughput, low memory usage, and reliable payload forwarding with HTTP Custom, NapsternetV, NetMod, DarkTunnel, and v2rayNG clients.

---

## Features

* **Async WebSocket & Payload Ingress Engine:**
  - Non-blocking I/O powered by Python `asyncio`.
  - Dynamic `Sec-WebSocket-Accept` computation via RFC 6455 handshake specification.
  - Lossless bidirectional stream forwarding optimized for HTTP Custom, NapsternetV, NetMod, and DarkTunnel.
  - Supports custom CDN bug hosts and WebSocket upgrade headers (`Upgrade: websocket`).
  - Standard HTTP ingress on port `80` and `8880`, with native TLS/WSS termination on port `443`.

* **Bandwidth Quotas & Multi-Login Limiter:**
  - Kernel-level iptables byte accounting per Linux user.
  - Real-time session monitoring with automatic disconnection of sessions exceeding `max_logins`.
  - Salted PBKDF2-SHA256 password hashing.

* **1-Click Self-Update Engine:**
  - Automated updates directly from official GitHub Releases.
  - Staging verification and Python bytecode syntax checks (`py_compile`) before code promotion.
  - Two-tier automated rollback (code snapshot + SQLite online backup) in case of health check failure.
  - Clean service management ensuring zero file-lock or race conditions during upgrades.

* **Decoupled Port Management:**
  - Ports are managed independently in `/etc/vextunnel/ports.env`.
  - Systemd service templates read environment variables directly, preserving user port overrides across updates.

* **Telegram Notifications & Automated Monthly Reset:**
  - Quota threshold alerts (80%, 90%, 100%) with alert deduplication.
  - Automated monthly bandwidth reset via systemd timer (1st of every month at 00:00 UTC).
  - On-demand database backup dispatch to Telegram.

* **BadVPN UDP Gateway:**
  - UDP forwarding on port `7300` for low-latency online gaming and VoIP calling.

* **Interactive Terminal Interface:**
  - Accessible anytime by typing `menu` in your terminal.
  - Real-time system monitoring (CPU, RAM, Disk, active connections, and service status).

---

## Installation

Run the following command as `root` on Debian 10+ or Ubuntu 20.04+ (x86_64 or ARM64):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/VoxelVoid-0/VexTunnel/main/install.sh)
```

---

## Updating VexTunnel

To update VexTunnel to the latest official release:

### Option 1: Via Management Menu (Interactive)
Run `menu` and choose option **15) Check for Updates**.

### Option 2: Via Terminal Command (Headless)
```bash
sudo python3 /etc/vextunnel/cli/menu.py --update
```

### Option 3: Standalone Shell Script
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/VoxelVoid-0/VexTunnel/main/install/update.sh)
```

---

## Usage

Launch the management menu by typing:

```bash
menu
```

```text
╔══════════════════════════════════════════════════════════════╗
║                    ⚡ VEXTUNNEL SUITE ⚡                     ║
║        Lightweight SSH-WebSocket Tunnel Manager for Linux    ║
╚══════════════════════════════════════════════════════════════╝
 Host / IP : 198.51.100.1 | OS: Linux | Uptime: 7d 6h
 RAM       : [███░░░░░░░] 30.8% (298MB/967MB)
 Disk      : [█░░░░░░░░░] 9.6% | Active Users: 1 | Online: 1 🟢
──────────────────────────────────────────────────────────────
[ SSH & WEBSOCKET USER MANAGEMENT ]
  1) Create SSH-WebSocket Account
  2) Renew User Subscription
  3) Reset User Password
  4) Reset User Bandwidth Quota
  5) Delete User Account
  6) Lock / Unlock User Account
  7) List All Registered Users
  8) Export Client Config & Payloads

[ SYSTEM & NETWORK CONTROLS ]
  9) Live Online Users Inspector (Real-time)
  10) Live Services Health Check
  11) Restart All Tunnel Services
  12) Domain & SSL Certificate Settings
  13) VPS Bandwidth Speedtest
  14) Telegram Notifications & Backups
  15) Check for Updates

  0) Exit
──────────────────────────────────────────────────────────────
Select an option [0-15]:
```

---

## Default Ports & Configuration

Default ports can be viewed or customized in `/etc/vextunnel/ports.env`:

| Service | Port | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **OpenSSH** | `22`, `2222` | TCP | Administrative SSH access |
| **Dropbear SSH** | `109`, `143` | TCP | Backend SSH target for proxy payloads |
| **WebSocket HTTP** | `80`, `8880` | TCP (HTTP/WS) | HTTP WebSocket payload ingress |
| **WebSocket HTTPS** | `443` | TCP (SSL/WSS) | Native TLS/SSL encrypted WebSocket ingress |
| **BadVPN UDPGW** | `7300` | UDP | Online gaming and VoIP packet forwarding |

---

## Uninstallation

To cleanly remove VexTunnel, systemd services, and configuration files from your server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/VoxelVoid-0/VexTunnel/main/install/uninstall.sh)
```

---

## License

Distributed under the [GNU General Public License v3.0](LICENSE) © 2026 VoxelVoid-0.
