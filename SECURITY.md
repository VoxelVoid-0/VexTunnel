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

4. **Subscription Portal & Cloudflare Zero Trust Hardening:**
   - **Origin Obfuscation & Localhost Binding:** The subscription server binds strictly to `127.0.0.1:8088`. Zero public inbound firewall ports are opened for the web portal. All web traffic is routed exclusively through the Cloudflare Zero Trust Named Tunnel (`cloudflared`).
   - **Cryptographic Tokens:** Subscription URLs use 128-bit cryptographically secure hex tokens generated via Python `secrets.token_hex(16)`.
   - **Pre-Database Regex Sanitization:** Inbound tokens are validated against `^[0-9a-f]{32}$` before querying SQLite, providing DoS and SQL injection immunity.
   - **In-Memory Rate Limiting:** A thread-safe rate limiter tracks real client IPs via `CF-Connecting-IP` (capped at 30 requests per minute per IP) returning `HTTP 429 Too Many Requests` upon violation.
   - **Concurrency & Non-Locking DB Reads:** The portal queries SQLite strictly via short-lived read-only URI connections (`mode=ro`), preventing `database is locked` contention with the real-time session enforcer.
   - **Credential Protection:** Cloudflare tunnel tokens are stored in `/etc/vextunnel/cf_tunnel.env` with `chmod 600` permissions and loaded via systemd `EnvironmentFile` to hide secrets from `ps aux` command-line inspections.

5. **Update Safety & Rollback:**
   - The self-update engine verifies archive integrity and compiles Python bytecode (`py_compile`) in staging before promoting code to production.
   - Automated two-tier rollback restores both codebase snapshots and SQLite native database backups if post-update health checks fail.

---

## Reporting a Vulnerability

If you discover a security vulnerability in VexTunnel, please report it responsibly:

* **Do not** report security vulnerabilities in public GitHub issues.
* Please submit a private security advisory through GitHub:
  [Report a Vulnerability](https://github.com/VoxelVoid-0/VexTunnel/security/advisories/new)
* You will receive an acknowledgment within 24 hours, followed by a patched release upon verification.
