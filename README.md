# ⚡ VexTunnel Suite

[![VexTunnel CI](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml)
[![Security Analysis](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64-orange.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](#)

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
```
╔══════════════════════════════════════════════════════════════╗
║                   ⚡ VEXTUNNEL SUITE v1.0 ⚡                 ║
║         Clean • High-Speed • Zero-Backdoor VPS Suite         ║
╚══════════════════════════════════════════════════════════════╝
 Server IP: 198.51.100.1 | RAM: 14.2% | Disk: 8.5% | Active Users: 1
──────────────────────────────────────────────────────────────
[ SSH & WEBSOCKET MANAGEMENT ]
  1) Create SSH-WebSocket Account
  2) Renew SSH User Account
  3) Delete SSH User Account
  4) List All Active Users & Expiry

[ SYSTEM & NETWORK CONTROLS ]
  5) Live Services Health Check
  6) Restart All Tunnel Services
  7) Private Telegram Backup (Send to YOUR Bot)

  0) Exit
──────────────────────────────────────────────────────────────
Select an option [0-7]:
```

---

## 🌐 Default Ports & Services

| Service | Port(s) | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **OpenSSH** | `22`, `2222` | TCP | Direct Administrative & Tunnel SSH |
| **Dropbear SSH** | `109`, `143` | TCP | Lightweight SSH for Payload Forwarding |
| **WebSocket HTTP** | `80`, `8880` | TCP (HTTP/WS) | Bug-Host & CDN WebSocket Ingress |
| **WebSocket HTTPS** | `443` | TCP (SSL/WSS) | SNI & Stunnel / Reverse Proxy |
| **BadVPN UDPGW** | `7100`, `7200`, `7300` | UDP | Online Gaming & VoIP Forwarding |

---

## 📄 License
Released under the [MIT License](LICENSE) © 2026 VexElvn.

