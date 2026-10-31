---
name: Bug Report
about: Create a report to help us fix a bug or issue in VexTunnel
title: "[BUG] "
labels: ["bug"]
assignees: ""
---

### 🐛 Describe the Bug
A clear and concise description of what the bug is.

### 🖥️ Server Environment
- **Operating System & Version**: [e.g. Debian 12, Ubuntu 22.04 LTS]
- **CPU Architecture**: [e.g. x86_64, aarch64 (ARM64)]
- **VexTunnel Version**: [e.g. v1.1-beta]
- **Tunnel Mode**: [Direct IP / Custom Domain]

### 📱 Client Information (if applicable)
- **VPN App**: [e.g. HTTP Injector, NetMod Syna, HTTP Custom, NapsternetV]
- **ISP / Mobile Operator**: [e.g. Mobitel, Dialog, SLT, Other]
- **Connection Type**: [HTTP Port 80 / HTTPS WSS Port 443]

### 🔄 Steps to Reproduce
1. Install / Run `...`
2. Create user with `...`
3. Connect client using payload `...`
4. See error: `...`

### 📋 Relevant Logs / Output
```text
Paste terminal output or systemctl status logs here:
journalctl -u vextunnel-ws -n 50 --no-pager
```

### 🎯 Expected Behavior
A clear and concise description of what you expected to happen.
