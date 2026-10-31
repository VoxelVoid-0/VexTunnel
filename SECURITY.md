# 🔒 Security Policy

## Supported Versions

The following versions of **VexTunnel** are currently being supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## 🛡️ Our Security Commitment

1. **Zero Backdoors & Zero Hidden Blobs:**
   - VexTunnel is built with 100% human-readable source code.
   - We strictly forbid encrypted or pre-compiled binaries disguised as scripts (such as the legacy SkyNode `lib_enc.sh` malware).
   - BadVPN is compiled directly from official source code (`ambrop72/badvpn`) on the target machine.

2. **Zero Telemetry & Absolute Privacy:**
   - VexTunnel transmits **zero telemetry**, server IP logs, or credentials to any third-party server.
   - Database records and user accounts remain strictly local to your VPS (`/etc/vextunnel/vextunnel.db`).
   - Telegram backup features (if enabled) communicate exclusively with **your own** private Telegram bot token.

3. **Least-Privilege User Isolation:**
   - All client tunnel accounts are provisioned with `/bin/false` restricted shells and no home directories (`-M`).
   - Administrative SSH access (`root`) is segregated from Dropbear tunnel ports (`109`, `143`).

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability or potential exploit in VexTunnel, please report it responsibly:

* **DO NOT** open a public GitHub issue.
* Please submit a private security advisory directly via GitHub:
  **GitHub Security Advisory:** [Report a Vulnerability](https://github.com/VoxelVoid-0/VexTunnel/security/advisories/new)
* You will receive an acknowledgment within 24 hours, followed by a patched release upon verification.
