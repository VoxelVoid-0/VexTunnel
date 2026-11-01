# ⚡ VexTunnel Suite

[![VexTunnel CI](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml)
[![Security Analysis](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64-orange.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](#)

> [!NOTE]
> **🚀 VexTunnel v1.2.0 - Production Hardened Release**:  
> VexTunnel v1.2.0 is an enterprise-grade, high-concurrency VPS tunneling platform featuring salted PBKDF2-SHA256 cryptographic security, strict RFC 6455 dynamic WebSocket protocol negotiation, kernel-level Linux UID byte quota enforcement, and authoritative session limit enforcement.

> **A 100% Clean, Modern, High-Performance SSH-WebSocket & VPS Tunneling Management Suite.**  
> Built from scratch with Zero Backdoors, Zero Telemetry, and Complete Transparency.  
> Developed for **VoxelVoid-0** (`https://github.com/VoxelVoid-0/VexTunnel`).

---

## 🌟 Key Features

* **⚡ Async Python WebSocket Engine (Strict RFC 6455):**
  - Non-blocking asynchronous I/O powered by Python `asyncio`.
  - Dynamic `Sec-WebSocket-Accept` computation via SHA-1 + RFC GUID (`258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).
  - Pre-backend validation gate with `HTTP/1.1 426 Upgrade Required` protection against unsupported protocols.
  - Supports all custom HTTP/CDN payloads (`Upgrade: websocket`, custom bug hosts) used by **HTTP Custom**, **NapsternetV**, **HTTP Injector**, **NetMod**, and **KPN Tunnel**.
  - Operates on HTTP ports `80` and `8880`, plus HTTPS `443` native TLS/WSS.

* **🔒 Enterprise Cryptographic Security:**
  - **Salted PBKDF2-SHA256:** Passwords hashed with 200,000 rounds and 16-byte random salt. Zero plaintext passwords stored or returned by APIs.
  - **Fail-Hard Atomic Migration:** Database migrations strictly roll back on corrupted legacy records without silent default passwords.
  - **SQLite WAL Mode:** Concurrency-safe Write-Ahead Logging with 5,000ms busy timeouts.

* **🌐 Kernel-Level UID Byte Quota Engine:**
  - Dedicated `VEXTUNNEL_QUOTA` and `VEXTUNNEL_BLOCK` iptables chains for isolated Linux UID bandwidth tracking.
  - Automatic disconnection and hardware DROP rule injection upon reaching monthly quota limits.
  - Zero-downtime quota resets with `iptables -Z` counter clearing.

* **👥 Authoritative Multi-Layer Session Tracking:**
  - Live session tracking via SQLite `active_sessions` synchronized with Dropbear process tables.
  - Multi-login limiter daemon auto-terminating rogue child processes exceeding `max_logins`.
  - OS-level `limits.conf` and `sshd_config` policies.

* **🛡️ Dual SSH Architecture:**
  - **Dropbear:** Extremely lightweight SSH daemon listening on ports `109` and `143`.
  - **OpenSSH:** Standard hardened SSH daemon on ports `22` and `2222`.

* **🎮 BadVPN UDP Gateway (Gaming & VoIP):**
  - Native compilation from official source (`ambrop72/badvpn`).
  - Active on UDP ports `7100`, `7200`, `7300` for low-latency online gaming (FreeFire, PUBG, Mobile Legends) and clear VoIP calling (WhatsApp, Discord).

* **📊 Interactive Terminal UI (TUI):**
  - Launchable anytime by typing `menu` in your terminal.
  - User creation with optional bandwidth quotas, password reset, quota unblock, and live status.
  - Real-time CPU, RAM, Disk, active connections, and service health monitoring.

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
║                  ⚡ VEXTUNNEL SUITE v1.2.0 ⚡                ║
║         Clean • High-Speed • Zero-Backdoor VPS Suite         ║
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
  14) Private Telegram Database Backup

  0) Exit
──────────────────────────────────────────────────────────────
Select an option [0-14]:
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

