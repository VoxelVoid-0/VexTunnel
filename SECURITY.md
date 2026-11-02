# Security Policy

## Supported Versions

The following versions of **VexTunnel** are currently supported with security and stability updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.3.x   | :white_check_mark: |
| < 1.3.0 | :x:                |

---

## Security Architecture

1. **Source Transparency:**
   - VexTunnel is built with 100% human-readable Python and Bash source code.
   - All helper components (such as BadVPN UDPGW) are built directly from their official open-source repositories.

2. **Data Privacy & Local Storage:**
   - VexTunnel transmits no telemetry, server IPs, or credentials to any remote service.
   - User credentials, session records, and bandwidth quotas remain strictly local to your server (`/etc/vextunnel/vextunnel.db`).
   - If Telegram notifications or backups are enabled, communications use your own private Telegram bot token directly via standard HTTPS requests.

3. **User Isolation & Principle of Least Privilege:**
   - Client tunnel user accounts are provisioned with `/bin/false` restricted shells and no user home directories.
   - Administrative SSH access (`root`) is segregated from Dropbear tunnel ports (`109`, `143`).
   - Passwords are encrypted using salted PBKDF2-SHA256 with 200,000 hashing rounds.

4. **Update Safety & Rollback:**
   - The self-update engine verifies archive integrity and compiles Python bytecode (`py_compile`) in staging before promoting code to production.
   - Automated two-tier rollback restores both codebase snapshots and SQLite native database backups if post-update health checks fail.

---

## Reporting a Vulnerability

If you discover a security vulnerability in VexTunnel, please report it responsibly:

* **Do not** report security vulnerabilities in public GitHub issues.
* Please submit a private security advisory through GitHub:
  [Report a Vulnerability](https://github.com/VoxelVoid-0/VexTunnel/security/advisories/new)
* You will receive an acknowledgment within 24 hours, followed by a patched release upon verification.
