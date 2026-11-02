## Description
<!-- Provide a brief summary of the changes in this pull request and the problem they solve. -->

## Type of Change
- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 📝 Documentation update
- [ ] ⚡ Performance optimization
- [ ] 🧪 Test suite enhancement

## PR Checklist
- [ ] My PR targets the **`main`** branch (Single-Branch architecture).
- [ ] I have executed the automated test suite locally: `python3 -m unittest discover tests` (all tests pass).
- [ ] My changes in `core/` and `cli/` rely strictly on the **Python Standard Library** (no heavy external pip dependencies).
- [ ] If modifying database schemas, the migration is idempotent and backward-compatible (zero data loss for existing users).
- [ ] If modifying systemd services, ports remain decoupled via `/etc/vextunnel/ports.env` using `Environment="PORT=..."` and `$PORT`.
- [ ] Shell scripts have been validated with `shellcheck`.
- [ ] No sensitive credentials, private keys, or debug tokens are committed.
