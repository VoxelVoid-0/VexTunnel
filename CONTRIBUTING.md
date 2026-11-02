# Contributing to VexTunnel

Thank you for your interest in contributing to **VexTunnel**! We welcome bug fixes, performance improvements, and documentation enhancements.

Please review the guidelines below to ensure a smooth contribution process.

---

## Architecture & Engineering Standards

To keep VexTunnel lightweight, reliable, and easily maintainable across Debian and Ubuntu distributions, all contributions should follow these principles:

1. **Python Standard Library in Core:**
   - Modules in `core/` and `cli/` should rely strictly on the **Python Standard Library** (e.g., `asyncio`, `socket`, `sqlite3`, `urllib`, `argparse`).
   - Avoid adding external pip dependencies to core modules so that fresh VPS installations remain fast, lean, and self-contained.

2. **Decoupled Configuration:**
   - Network ports must remain configurable via `/etc/vextunnel/ports.env`.
   - Never hardcode ports directly in systemd `.service` files; use `Environment="PORT=..."` and `$PORT` expansion.

3. **Database Schema Compatibility:**
   - Any changes to the SQLite database schema must be idempotent and backward-compatible.
   - Use `PRAGMA table_info` to detect existing columns and apply migrations without data loss.

4. **Input Sanitization & Security:**
   - All user inputs (usernames, passwords, ports, domains) must be validated to prevent shell command injection and SQL injection.

---

## Local Development & Testing

### 1. Fork & Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/VexTunnel.git
cd VexTunnel
git checkout -b feat/your-feature-name
```

### 2. Run the Automated Test Suite
Before submitting any changes, ensure all unit tests pass:
```bash
python3 -m unittest discover tests
```

### 3. Lint Shell Scripts
If you modify any shell scripts in `install/` or `install.sh`:
```bash
shellcheck -e SC2034,SC2181 install/*.sh install.sh
```

---

## Git Workflow & Pull Requests

1. **Target Branch:**
   - VexTunnel uses a **Single-Branch (`main`)** distribution model. All feature branches and pull requests should target **`main`**.

2. **Commit Conventions:**
   - We follow the [Conventional Commits](https://www.conventionalcommits.org/) format:
     - `feat: add support for custom cipher suites`
     - `fix: resolve dropbear pid parsing edge-case`
     - `docs: update installation instructions in README`
     - `test: add unit tests for port conflict validator`
     - `refactor: simplify socket connection logic`

3. **Submitting a Pull Request:**
   - Open a PR against the `main` branch.
   - Fill out the provided [Pull Request Template](.github/pull_request_template.md).
   - Ensure all automated GitHub Actions CI checks pass green.

---

## Reporting Issues & Security

- **Bug Reports & Feature Requests:** Please use the issue templates provided in `.github/ISSUE_TEMPLATE/`.
- **Security Vulnerabilities:** Follow our [Security Policy](SECURITY.md) and report vulnerabilities privately through [GitHub Security Advisories](https://github.com/VoxelVoid-0/VexTunnel/security/advisories/new).
