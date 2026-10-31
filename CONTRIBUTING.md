# 🤝 Contributing to VexTunnel

Thank you for your interest in contributing to **VexTunnel**! We welcome bug fixes, performance improvements, and documentation enhancements from the open-source community.

To maintain our core promise of **Zero-Backdoor, High-Performance, and Clean Production Code**, please review the following guidelines before submitting a pull request.

---

## 📜 Core Contribution Principles

1. **Zero External Dependencies in Core**:
   - `core/` and `cli/` must run strictly using the **Python Standard Library** (no heavy external pip dependencies like `requests`, `aiohttp`, etc.).
   - This ensures instant zero-delay installation on fresh VPS instances with zero supply-chain risk.

2. **Absolute Transparency & No Obfuscated Code**:
   - Never submit pre-compiled binaries, base64-encoded shell strings, or encrypted scripts.
   - All shell scripts in `install/` must be 100% human-readable and pass ShellCheck.

3. **Strict Input Sanitization**:
   - All user inputs (usernames, passwords, ports, domains) must be validated to prevent command injection (`admin; rm -rf /`) and SQL injection.

---

## 🛠️ Local Development & Testing

### 1. Fork & Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/VexTunnel.git
cd VexTunnel
git checkout -b feat/your-feature-name
```

### 2. Run Automated Test Suite
Before submitting any changes, ensure all unit and security tests pass:
```bash
python -m unittest discover -s tests -v
```

### 3. Run Shell Script Linter (ShellCheck)
If you modify any shell scripts in `install/` or `install.sh`:
```bash
shellcheck -e SC2034,SC2181 install/*.sh install.sh
```

### 4. Run Python Security Audit (Bandit)
Ensure your code introduces zero security vulnerabilities:
```bash
pip install bandit
bandit -r core/ cli/ -ll
```

---

## 🌿 Git Branching & Pull Request Process

1. **Branching Strategy**:
   - `main`: Production-ready, stable releases.
   - `develop`: Active development and feature staging.
   - Always base your feature or bugfix branches off **`develop`**!

2. **Commit Conventions**:
   - Use Conventional Commits formatting:
     - `feat: add support for custom cipher suites`
     - `fix: resolve dropbear pid parsing edge-case`
     - `docs: update installation instructions in README`
     - `test: add unit tests for port conflict validator`

3. **Submitting a Pull Request**:
   - Target the **`develop`** branch for PRs.
   - Provide a clear description of the problem solved and testing steps performed.
   - Ensure all automated GitHub Actions CI checks pass.

---

## 🐞 Reporting Issues

- **Bug Reports**: Use our [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md) with full logs, OS details, and reproduction steps.
- **Feature Requests**: Use our [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md).
- **Security Vulnerabilities**: Please follow our [Security Policy](SECURITY.md) and report privately via [GitHub Security Advisories](https://github.com/VoxelVoid-0/VexTunnel/security/advisories/new).
