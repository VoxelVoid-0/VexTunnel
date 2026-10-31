# ⚡ VexTunnel Suite

[![VexTunnel CI](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml)
[![Security Analysis](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64-orange.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](#)

> [!WARNING]
> **🚀 Active Testing & Community Beta Release (v1.1-beta)**:  
> VexTunnel is currently under active community testing and development. While all core services are audited, hardened, and 100% zero-backdoor, please test in staging or development VPS instances before deploying for critical commercial operations. Full LTS release coming soon!

> **A 100% Clean, Modern, High-Performance SSH-WebSocket & VPS Tunneling Management Suite.**  
> Built from scratch with Zero Backdoors, Zero Telemetry, and Complete Transparency.  
> Developed for **VoxelVoid-0** (`https://github.com/VoxelVoid-0/VexTunnel`).

---

## 🌟 Key Features

* **⚡ Async Python WebSocket Engine:**
  - Non-blocking asynchronous I/O powered by Python `asyncio`.
  - Supports all custom HTTP/CDN payloads (`Upgrade: websocket`, custom bug hosts) used by **HTTP Custom**, **NapsternetV**, **HTTP Injector**, **NetMod**, and **KPN Tunnel**.
  - Operates on HTTP ports `80` and `8880` (with HTTPS `443` support via reverse proxy).

* **🛡️ Dual SSH Architecture:**
  - **Dropbear:** Extremely lightweight SSH daemon listening on ports `109` and `143`.
  - **OpenSSH:** Standard hardened SSH daemon on ports `22` and `2222`.

* **🎮 BadVPN UDP Gateway (Gaming & VoIP):**
  - Native compilation from official source (`ambrop72/badvpn`).
  - Active on UDP ports `7100`, `7200`, `7300` for low-latency online gaming (FreeFire, PUBG, Mobile Legends) and clear VoIP calling (WhatsApp, Discord).

* **📊 Interactive Terminal UI (TUI):**
  - Launchable anytime by typing `menu` in your terminal.
  - User creation, expiry management, live user listing, renewal, and deletion.
  - Real-time CPU, RAM, Disk, and service health monitoring.

* **🔒 Security & Privacy by Design:**
  - **SQLite Database:** Local user storage with proper expiration timestamps.
  - **No Obfuscation:** 100% clean, human-readable Python & Bash scripts. No hidden ELF binaries disguised as `.sh`.
  - **Safe Expiry Cleanup:** Automatically locks expired accounts without destructive commands or file deletion.
  - **Private Telegram Backup:** Backups are sent directly to **your** personal Telegram bot. Zero data leaves your control.
  - **UFW Firewall Hardened:** Explicitly opens required ports while protecting the rest of your server.

---

## 🚀 Quick Setup (Ubuntu / Debian VPS)

### One-Line Automated Installer
Run the following command as `root` on any fresh Debian/Ubuntu VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/VoxelVoid-0/VexTunnel/main/install.sh)
```

*Or via curl pipe:*
```bash
curl -fsSL https://raw.githubusercontent.com/VoxelVoid-0/VexTunnel/main/install.sh | bash
```

*Or via Git Clone:*
```bash
apt update -y && apt install -y git && git clone https://github.com/VoxelVoid-0/VexTunnel.git /etc/vextunnel && cd /etc/vextunnel && bash install.sh
```

---

## 🕹️ Usage

Once installed, simply type:
```bash
menu
```

The interactive management interface will appear:
```text
╔══════════════════════════════════════════════════════════════╗
║                   ⚡ VEXTUNNEL SUITE v1.1 ⚡                 ║
║         Clean • High-Speed • Zero-Backdoor VPS Suite         ║
╚══════════════════════════════════════════════════════════════╝
 Host / IP : 198.51.100.1 | OS: Linux | Uptime: 7d 6h
 RAM       : [███░░░░░░░] 30.8% (298MB/967MB)
 Disk      : [█░░░░░░░░░] 9.6% | Active Users: 1 | Online: 1 🟢
──────────────────────────────────────────────────────────────
[ SSH & WEBSOCKET USER MANAGEMENT ]
  1) Create SSH-WebSocket Account
  2) Renew User Account
  3) Delete User Account
  4) Lock / Unlock User Account
  5) List All Registered Users
  6) Export Client Config & Ready-to-Copy Payloads

[ SYSTEM & NETWORK CONTROLS ]
  7) Live Online Users Inspector (Real-time)
  8) Live Services Health Check
  9) Restart All Tunnel Services
  10) Domain & SSL Certificate Settings
  11) VPS Bandwidth Speedtest
  12) Private Telegram Database Backup

  0) Exit
──────────────────────────────────────────────────────────────
Select an option [0-12]:
```

---

## 🌐 Default Ports & Services

| Service | Port(s) | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **OpenSSH** | `22`, `2222` | TCP | Direct Administrative & Tunnel SSH |
| **Dropbear SSH** | `109`, `143` | TCP | Lightweight SSH for Payload Forwarding |
| **WebSocket HTTP** | `80`, `8880` | TCP (HTTP/WS) | Bug-Host & CDN WebSocket Ingress |
| **WebSocket HTTPS** | `443` | TCP (SSL/WSS) | Native TLS/SSL Encrypted WebSocket |
| **BadVPN UDPGW** | `7100`, `7200`, `7300` | UDP | Online Gaming & VoIP Forwarding |

---

## 📄 License
Released under the [MIT License](LICENSE) © 2026 VoxelVoid-0.

