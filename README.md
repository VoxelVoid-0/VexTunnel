# ⚡ VexTunnel Suite

[![VexTunnel CI](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/ci.yml)
[![Security Analysis](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml/badge.svg)](https://github.com/VoxelVoid-0/VexTunnel/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64-orange.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](#)

> [!NOTE]
> **🚀 VexTunnel v1.3.0 - Enterprise Resilience & Automation Release**:  
> VexTunnel v1.3.0 is a production-grade, high-concurrency VPS tunneling platform featuring sliding-window IP rate limiting, automated self-healing supervisor watchdogs with circuit breaker, real-time Telegram quota alerting with anti-spam deduplication, scheduled monthly bandwidth auto-resets, and modern CMake 4.x / Ubuntu 24.04+ compatibility.

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

* **🛡️ Kernel Anti-Abuse & Sliding-Window IP Rate Limiter:**
  - Sliding-window handshake throttle (max 20 handshakes / 5s) and per-IP concurrent connection cap (32 connections/IP) protecting against DoS.
  - Automatic background pruning of stale IP state entries to eliminate memory leaks.
  - Dedicated `VEXTUNNEL_LIMIT` iptables kernel chain using `hashlimit` module defending ports 80, 443, 109, and 22 against SYN flood abuse.

* **🩺 Self-Healing Supervisor Watchdog & Health Doctor:**
  - Daemon supervisor actively monitoring core services (`vextunnel-ws`, `vextunnel-wss`, `vextunnel-enforcer`, `dropbear`, `badvpn-7300`).
  - Automated restart recovery with integrated **Circuit Breaker** (pauses restarts if a service crashes > 5 times in 120s to avoid infinite restart loops).
  - Built-in `VexTunnelDoctor` checking SQLite B-tree integrity (`PRAGMA integrity_check`), missing firewall chains auto-recreation, port probes, and SSL cert validity with 1-click self-repair in TUI Option 10.

* **📱 Telegram Quota Alert Engine & Automated Monthly Reset:**
  - Zero-dependency Telegram Bot API client powered by Python standard library `urllib` (ultra-lightweight for 512MB RAM VPS).
  - Multi-tier quota alerts: ⚠️ 80% Warning, 🚨 90% Critical, and 🚫 100% Exceeded Cutoff.
  - **Anti-Spam Alert Deduplication**: SQLite schema tracks `last_quota_alert_pct` ensuring admin is alerted exactly once per threshold level.
  - Automated monthly bandwidth quota resets via Linux Systemd Timer (`vextunnel-quota-reset.timer` on the 1st of every month at 00:00 UTC).
  - TUI Option 14 **Telegram Bot Alerts & Backup Hub** with credential management, immediate test alerts, and database backup dispatch.

* **🔒 Enterprise Cryptographic Security:**
  - **Salted PBKDF2-SHA256:** Passwords hashed with 200,000 rounds and 16-byte random salt. Zero plaintext passwords stored or returned by APIs.
  - **Fail-Hard Atomic Migration:** Database migrations strictly roll back on corrupted legacy records without silent default passwords.
  - **SQLite WAL Mode:** Concurrency-safe Write-Ahead Logging with 5,000ms busy timeouts.

* **🌐 Kernel-Level UID Byte Quota Engine:**
  - Dedicated `VEXTUNNEL_QUOTA` and `VEXTUNNEL_BLOCK` iptables chains for isolated Linux UID bandwidth tracking.
  - Delta-based accounting ensuring bandwidth usage counters survive server reboots and firewall flushes.
  - Automatic disconnection and hardware DROP rule injection upon reaching monthly quota limits.

* **👥 Authoritative Multi-Layer Session Tracking:**
  - Live session tracking via SQLite `active_sessions` synchronized with Dropbear process tables.
  - Multi-login limiter daemon auto-terminating rogue child processes exceeding `max_logins`.
  - Unified OpenSSH & Dropbear tracking.

* **🎮 BadVPN UDP Gateway (Gaming & VoIP):**
  - Native compilation from official source (`ambrop72/badvpn`).
  - Modern CMake 4.x & Ubuntu 24.04/26.04 compatibility patches with verified pre-compiled fallback.
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
║                  ⚡ VEXTUNNEL SUITE v1.3.0 ⚡                ║
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
  10) System Diagnostics & Self-Healing Doctor
  11) Restart All Tunnel Services
  12) Domain & SSL Certificate Settings
  13) VPS Bandwidth Speedtest
  14) Telegram Bot Alerts & Backup Hub

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

## 🗑️ Clean Uninstallation

To completely and cleanly remove VexTunnel Suite, systemd daemons, firewall chains, binaries, and configurations from your VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/VoxelVoid-0/VexTunnel/main/install/uninstall.sh)
```

---

## 📄 License
Released under the [MIT License](LICENSE) © 2026 VoxelVoid-0.
