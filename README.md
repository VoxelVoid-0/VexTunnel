# ⚡ VexTunnel

[![VexTunnel CI](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml)
[![Security Analysis](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/VoxelVoid-0/VexTunnel?color=blue&logo=github)](https://github.com/VoxelVoid-0/VexTunnel/releases/latest)
[![Latest Release Downloads](https://img.shields.io/github/downloads/VoxelVoid-0/VexTunnel/latest/total?color=blue&label=latest%20downloads&logo=github)](https://github.com/VoxelVoid-0/VexTunnel/releases/latest)
[![Total Downloads](https://img.shields.io/github/downloads/VoxelVoid-0/VexTunnel/total?color=brightgreen&label=total%20downloads&logo=github)](https://github.com/VoxelVoid-0/VexTunnel/releases)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64-orange.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](#)

A high-performance, ultra-lightweight SSH-over-WebSocket proxy and tunneling manager for Linux VPS. Engineered for maximum bandwidth throughput, low memory footprint (< 12MB core daemons), and lossless bidirectional payload forwarding for HTTP Custom, NapsternetV, NetMod, DarkTunnel, and v2rayNG clients.

---

## 🌟 Key Features

* **Client Subscription Web Portal & RESTful API:**
  - Zero-dependency, ultra-lightweight HTTP daemon (< 12MB RAM) binding strictly to `127.0.0.1:8088`.
  - Responsive **3x-ui styled dark slate dashboard** (`#0b0f19`) displaying real-time used traffic, remaining bandwidth quota, subscription expiration date, days left, and account status badges.
  - Live client-side auto-refresh (every 60s) polling `/sub/<token>?format=json` for seamless real-time updates without page reloads.
  - Pre-database regex validation (32-char lowercase hex) and in-memory rate limiting (30 req/min per IP via `CF-Connecting-IP`).
  - Read-Only SQLite URI mode (`mode=ro`) preventing database lock contention with active proxy sessions.

* **Cloudflare Zero Trust Named Tunnel Integration:**
  - Securely exposes client subscription portals via custom domain (e.g., `sub.yourdomain.com`).
  - **Zero open inbound public ports** on the VPS for the web portal (origin server IP is 100% hidden behind Cloudflare Edge).
  - Protected token storage in `/etc/vextunnel/cf_tunnel.env` (`chmod 600`) and shielded from process snooping via systemd `EnvironmentFile`.
  - Automated 1-click token setup and daemon control via CLI Menu Option 17.

* **Kernel-Level Bidirectional Accounting (`CONNMARK`):**
  - Powered by Linux netfilter connection tracking (`iptables -t mangle CONNMARK`).
  - Accurately captures **100% of both Ingress (Download) and Egress (Upload)** payload traffic.
  - Zero packet leakage: full accuracy for large file downloads (Telegram, MEGA), high-bitrate streaming (YouTube, Netflix), and interactive browsing.

* **Async WebSocket & Payload Ingress Engine:**
  - High-concurrency non-blocking I/O powered by Python `asyncio`.
  - Dynamic `Sec-WebSocket-Accept` computation conforming to the RFC 6455 handshake specification.
  - Lossless bidirectional stream forwarding optimized for HTTP Custom, NapsternetV, NetMod, and DarkTunnel.
  - Supports custom CDN bug hosts and WebSocket upgrade headers (`Upgrade: websocket`).
  - Standard HTTP ingress on port `80` and `8880`, with native TLS/WSS termination on port `443`.

* **3x-ui / Xray Non-Destructive Port Co-existence:**
  - 1-click toggle to yield or reclaim Port 443 without disrupting existing Xray or 3x-ui panels.
  - Dynamic port management with automatic iptables rule synchronization.

* **Multi-Port BadVPN UDP Gateway:**
  - Concurrent UDP packet forwarding across ports `7100`, `7200`, and `7300` for low-latency online gaming and VoIP calls.
  - Robust systemd integration with dynamic port expansion.

* **Multi-Login Limiter & Session Enforcer:**
  - Real-time session monitoring daemon enforcing `max_logins` limits across active Dropbear and OpenSSH connections.
  - Salted PBKDF2-SHA256 password hashing (200,000 rounds) with strict credential isolation.

* **Telegram Notifications & Automated Monthly Reset:**
  - Bandwidth quota threshold alerts (80%, 90%, 100%) with alert deduplication.
  - Automated monthly bandwidth reset via systemd timer (1st of every month at 00:00 UTC).
  - On-demand database backup dispatch to Telegram.

* **1-Click Self-Update Engine:**
  - Automated updates directly from official GitHub Releases.
  - Staging verification and Python bytecode syntax checks (`py_compile`) before code promotion.
  - Two-tier automated rollback (code snapshot + SQLite online backup) in case of health check failure.

---

## 🚀 Installation

Run the following command as `root` on Debian 10+ or Ubuntu 20.04+ (x86_64 or ARM64):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/VoxelVoid-0/VexTunnel/main/install.sh)
```

---

## 🔄 Updating VexTunnel

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

## 🖥️ Management Menu

Launch the interactive management panel anytime by typing:

```bash
menu
```

```text
╔══════════════════════════════════════════════════════════════╗
║                 ⚡ VEXTUNNEL SUITE v1.3.14 ⚡                  ║
║      Lightweight SSH-WebSocket Tunnel Manager for Linux      ║
╚══════════════════════════════════════════════════════════════╝
 Host / IP : vps.example.com | OS: Linux | Uptime: 8d 14h
 RAM       : [█░░░░░░░░░] 6.7% (801MB/11924MB)
 Disk      : [░░░░░░░░░░] 4.9% | Active Users: 6 | Online: 2 🟢
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
  16) Service Ports & Co-existence Manager
  17) Subscription Portal & Cloudflare Zero Trust

  0) Exit
──────────────────────────────────────────────────────────────
Select an option [0-17]:
```

---

## 🌐 Client Subscription Portal & Cloudflare Setup

VexTunnel provides each client account with a personalized, tamper-resistant subscription card displaying live data usage and expiration dates.

### Step 1: Configure Cloudflare Zero Trust Tunnel
1. Go to your [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/) > **Networks** > **Tunnels**.
2. Click **Create a Tunnel**, choose **Cloudflared**, and copy your **Tunnel Token**.
3. Under the **Public Hostnames** tab of your tunnel, add a route:
   - **Subdomain / Domain:** e.g., `sub.yourdomain.com`
   - **Service Type:** `HTTP`
   - **URL:** `127.0.0.1:8088`
4. On your VPS terminal, launch `menu`, select **Option 17**, and choose:
   - **1) Configure Tunnel Token:** Paste your tunnel token.
   - **2) Set Custom Subdomain:** Enter your public hostname (e.g. `sub.yourdomain.com`).

### Step 2: Share Subscription Links with Clients
- In `menu` > **Option 17** > choose **5) View Client Subscription Links**.
- Individual links follow the format:
  `https://sub.yourdomain.com/sub/<unique_32_character_token>`
- Clients can view their data consumption in real time, and third-party bots can query the JSON API by appending `?format=json`.

---

## 🔌 Default Ports & Configuration

Default ports can be customized at any time in `/etc/vextunnel/ports.env` or via **Menu Option 16**:

| Service | Port | Protocol | Scope | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **OpenSSH** | `22`, `2222` | TCP | Public | Administrative SSH access |
| **Dropbear SSH** | `109`, `143` | TCP | Loopback / Public | Backend SSH target for proxy payloads |
| **WebSocket HTTP** | `80`, `8880` | TCP (HTTP/WS) | Public | Cleartext WebSocket payload ingress |
| **WebSocket HTTPS** | `443` | TCP (SSL/WSS) | Public | Native TLS/SSL encrypted WebSocket ingress (can be yielded to 3x-ui) |
| **BadVPN UDPGW** | `7100`, `7200`, `7300` | TCP / UDP | Loopback | UDP gateway forwarding for gaming & VoIP |
| **Subscription Portal** | `8088` | TCP (HTTP) | Localhost strictly | Internal web portal routed exclusively via Cloudflare Zero Trust |

---

## 🗑️ Uninstallation

To cleanly remove VexTunnel, all background daemons, firewall chains, and configuration files from your server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/VoxelVoid-0/VexTunnel/main/install/uninstall.sh)
```

---

## 📄 License

Distributed under the [GNU General Public License v3.0](LICENSE) © 2026 VoxelVoid-0.
