#!/usr/bin/env python3
"""
Unit tests for RFC 6455 dynamic WebSocket handshake calculations,
clean database migration without legacy password columns,
and kernel-level quota management.
"""

import unittest
from unittest import mock
import os
import sqlite3
import tempfile
import shutil
import base64
import hashlib

from core.ws_proxy import (
    compute_websocket_accept,
    parse_http_headers,
    SSHWebSocketProxy,
    WS_GUID
)
from core.user_manager import UserManager, hash_password
from core.quota_manager import (
    format_bytes,
    parse_bytes,
    reset_user_quota
)

class TestRFC6455AndQuota(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_vextunnel.db")

    def tearDown(self):
        for u in ["testalice", "legacybob", "authuser", "quotauser", "nouiduser", "lockedquota", "expiredquota"]:
            try:
                if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
                    import subprocess
                    subprocess.run(["userdel", "-f", u], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_rfc6455_official_test_vector(self):
        """Verify RFC 6455 official specification example vector."""
        # Standard RFC 6455 Section 4.2.2 example
        client_key = "dGhlIHNhbXBsZSBub25jZQ=="
        expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

        calculated = compute_websocket_accept(client_key)
        self.assertEqual(calculated, expected_accept)

    def test_rfc6455_dynamic_handshake_response(self):
        """Test proxy generates dynamic RFC 6455 101 Switching Protocols response."""
        proxy = SSHWebSocketProxy(
            listen_host="127.0.0.1",
            listen_port=8080,
            target_host="127.0.0.1",
            target_port=109,
            response_code=101
        )
        sample_key = "x3JJHMbDL1EzLkh9GBhXDw=="
        resp = proxy.build_handshake_response(client_key=sample_key)

        expected_accept = compute_websocket_accept(sample_key)
        self.assertIn(b"HTTP/1.1 101 Switching Protocols", resp)
        self.assertIn(b"Upgrade: websocket", resp)
        self.assertIn(f"Sec-WebSocket-Accept: {expected_accept}".encode("ascii"), resp)

    def test_http_header_parser(self):
        """Test parser extracts lowercase header dictionary accurately."""
        raw_req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        headers = parse_http_headers(raw_req)
        self.assertEqual(headers.get("upgrade"), "websocket")
        self.assertEqual(headers.get("connection"), "Upgrade")
        self.assertEqual(headers.get("sec-websocket-key"), "dGhlIHNhbXBsZSBub25jZQ==")
        self.assertEqual(headers.get("host"), "example.com")

    def test_clean_schema_no_password_column(self):
        """Verify that SQLite users table has NO legacy 'password' column."""
        mgr = UserManager(self.db_path)
        mgr.add_user("testalice", "SecureSecretPass123", 30)

        conn = sqlite3.connect(self.db_path)
        cols = [col[1] for col in conn.execute("PRAGMA table_info(users)").fetchall()]
        conn.close()

        self.assertNotIn("password", cols, "Legacy plaintext password column must not exist!")
        self.assertIn("password_hash", cols)
        self.assertIn("quota_bytes", cols)
        self.assertIn("used_bytes", cols)

    def test_legacy_database_hard_migration(self):
        """Test that opening a legacy DB with 'password' column triggers hard migration and drops it."""
        # Create legacy DB table manually
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT,
                protocol TEXT DEFAULT 'ssh-ws',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                max_logins INTEGER DEFAULT 1,
                status TEXT DEFAULT 'active'
            )
        """)
        conn.execute("""
            INSERT INTO users (username, password, expires_at)
            VALUES ('legacybob', 'OldPlainPass123', '2030-01-01 00:00:00')
        """)
        conn.commit()
        conn.close()

        # Instantiate UserManager which should trigger hard migration
        mgr = UserManager(self.db_path)
        user_list = mgr.list_users()
        bob = next((u for u in user_list if u["username"] == "legacybob"), None)
        self.assertIsNotNone(bob)
        self.assertTrue(bob["password_hash"].startswith("pbkdf2_sha256$"))

        # Check schema
        conn = sqlite3.connect(self.db_path)
        cols = [col[1] for col in conn.execute("PRAGMA table_info(users)").fetchall()]
        conn.close()
        self.assertNotIn("password", cols)

        # Authenticate should work against migrated hash
        self.assertTrue(mgr.authenticate_user("legacybob", "OldPlainPass123"))

    def test_authoritative_authentication(self):
        """Test UserManager.authenticate_user() verifies valid and rejects invalid credentials."""
        mgr = UserManager(self.db_path)
        mgr.add_user("authuser", "CorrectPassword123", 30)

        self.assertTrue(mgr.authenticate_user("authuser", "CorrectPassword123"))
        self.assertFalse(mgr.authenticate_user("authuser", "WrongPassword999"))
        self.assertFalse(mgr.authenticate_user("nonexistent", "CorrectPassword123"))

        # Lock user and verify auth fails
        mgr.lock_user("authuser")
        self.assertFalse(mgr.authenticate_user("authuser", "CorrectPassword123"))

    def test_quota_formatting_and_parsing(self):
        """Test parse_bytes and format_bytes conversions."""
        self.assertEqual(parse_bytes("0"), 0)
        self.assertEqual(parse_bytes("1"), 1024**3)
        self.assertEqual(parse_bytes("10"), 10 * 1024**3)
        self.assertEqual(parse_bytes("500M"), 500 * 1024 * 1024)
        self.assertEqual(parse_bytes("50G"), 50 * 1024 * 1024 * 1024)
        self.assertEqual(parse_bytes("2TB"), 2 * 1024**4)
        self.assertEqual(parse_bytes("100B"), 100)

        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1073741824), "1.00 GB")

    def test_quota_reset_functionality(self):
        """Test resetting quota resets used_bytes to 0 and reactivates user status."""
        mgr = UserManager(self.db_path)
        mgr.add_user("quotauser", "SecretPass123", 30, quota_bytes=1000)

        # Simulate exceeded quota
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE users SET used_bytes = 2000, quota_status = 'quota_exceeded', status = 'quota_exceeded' WHERE username = 'quotauser'")
        conn.commit()
        conn.close()

        # Auth should be blocked while quota is exceeded
        self.assertFalse(mgr.authenticate_user("quotauser", "SecretPass123"))

        reset_success = reset_user_quota("quotauser", self.db_path)
        self.assertTrue(reset_success)

        users = mgr.list_users()
        qu = next(u for u in users if u["username"] == "quotauser")
        self.assertEqual(qu["used_bytes"], 0)
        self.assertEqual(qu["status"], "active")
        self.assertEqual(qu["quota_status"], "active")

        # Auth succeeds after reset
        self.assertTrue(mgr.authenticate_user("quotauser", "SecretPass123"))

    def test_quota_reset_preserves_locked_status(self):
        """Verify resetting quota on an administratively locked user does not reactivate account."""
        mgr = UserManager(self.db_path)
        mgr.add_user("lockedquota", "SecretPass123", 30, quota_bytes=1000)
        mgr.lock_user("lockedquota")

        # Confirm locked
        self.assertFalse(mgr.authenticate_user("lockedquota", "SecretPass123"))

        # Reset quota
        self.assertTrue(reset_user_quota("lockedquota", self.db_path))

        users = mgr.list_users()
        lu = next(u for u in users if u["username"] == "lockedquota")
        self.assertEqual(lu["used_bytes"], 0)
        self.assertEqual(lu["status"], "locked", "Locked status must NOT be overridden to active on quota reset")
        self.assertEqual(lu["quota_status"], "active")

    def test_quota_reset_preserves_expired_status(self):
        """Verify resetting quota on an expired account preserves expired status and denies unblock."""
        mgr = UserManager(self.db_path)
        # Add user that expired yesterday (-1 day)
        mgr.add_user("expiredquota", "SecretPass123", -1, quota_bytes=1000)

        self.assertFalse(mgr.authenticate_user("expiredquota", "SecretPass123"))

        # Reset quota
        self.assertTrue(reset_user_quota("expiredquota", self.db_path))

        users = mgr.list_users()
        eu = next(u for u in users if u["username"] == "expiredquota")
        self.assertEqual(eu["used_bytes"], 0)
        self.assertEqual(eu["status"], "expired", "Expired account must NOT be reactivated on quota reset")

    def test_migration_fails_hard_on_unhashable_legacy_row(self):
        """Test that unhashable legacy rows trigger strict transaction rollback without silent fallback."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT,
                protocol TEXT DEFAULT 'ssh-ws',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                max_logins INTEGER DEFAULT 1,
                status TEXT DEFAULT 'active'
            )
        """)
        # Insert corrupted row without password
        conn.execute("""
            INSERT INTO users (username, password, expires_at)
            VALUES ('brokenuser', NULL, '2030-01-01 00:00:00')
        """)
        conn.commit()
        conn.close()

        # Migration must fail hard and raise RuntimeError
        with self.assertRaises(RuntimeError) as ctx:
            UserManager(self.db_path)

        self.assertIn("Database migration aborted", str(ctx.exception))
        self.assertIn("brokenuser", str(ctx.exception))

        # Verify rollback: original table exists with original data intact
        conn = sqlite3.connect(self.db_path)
        cols = [c[1] for c in conn.execute("PRAGMA table_info(users)").fetchall()]
        self.assertIn("password", cols, "Table must roll back to legacy schema on abort")
        conn.close()

    def test_rfc6455_version_validation(self):
        """Test that proxy header parser accurately detects Sec-WebSocket-Version."""
        raw_req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 8\r\n\r\n"
        )
        headers = parse_http_headers(raw_req)
        self.assertEqual(headers.get("sec-websocket-version"), "8")

    def test_sync_bandwidth_quotas_user_without_uid(self):
        """Test sync_all_quotas gracefully handles users with no OS UID without UnboundLocalError."""
        from core.quota_manager import sync_all_quotas
        mgr = UserManager(self.db_path)
        with mock.patch("os.geteuid", return_value=1000, create=True):
            mgr.add_user("nouiduser", "Pass123!", days=30, max_logins=2, quota_bytes=100 * 1024 * 1024)
            with mock.patch("core.quota_manager.get_user_uid", return_value=None):
                summary = sync_all_quotas(self.db_path)
                self.assertIn("nouiduser", summary)
                self.assertEqual(summary["nouiduser"]["status"], "active")

    def test_init_firewall_chains_positioning(self):
        """Test init_firewall_chains ensures VEXTUNNEL_BLOCK and VEXTUNNEL_QUOTA are at top of OUTPUT."""
        from core.quota_manager import init_firewall_chains
        commands_run = []

        def fake_run(cmd, *args, **kwargs):
            commands_run.append(cmd)
            # Simulate iptables -S OUTPUT with UFW rules before VEXTUNNEL_QUOTA
            if cmd[:2] == ["iptables", "-S"]:
                mock_res = mock.MagicMock()
                mock_res.stdout = (
                    "-P OUTPUT ACCEPT\n"
                    "-A OUTPUT -j ufw-before-output\n"
                    "-A OUTPUT -j ufw-track-output\n"
                    "-A OUTPUT -j VEXTUNNEL_QUOTA\n"
                )
                mock_res.returncode = 0
                return mock_res
            res = mock.MagicMock()
            res.returncode = 0
            return res

        with mock.patch("os.name", "posix"):
            with mock.patch("os.geteuid", return_value=0, create=True):
                with mock.patch("subprocess.run", side_effect=fake_run):
                    res = init_firewall_chains()
                    self.assertTrue(res)

                    # Verify that mispositioned VEXTUNNEL_QUOTA was deleted and re-inserted at top
                    deleted = any(c[:4] == ["iptables", "-D", "OUTPUT", "-j"] and c[4] == "VEXTUNNEL_QUOTA" for c in commands_run)
                    inserted_quota = any(c[:3] == ["iptables", "-I", "OUTPUT"] and "VEXTUNNEL_QUOTA" in c for c in commands_run)
                    inserted_block = any(c[:3] == ["iptables", "-I", "OUTPUT"] and "VEXTUNNEL_BLOCK" in c for c in commands_run)
                    self.assertTrue(deleted, "Mispositioned VEXTUNNEL_QUOTA after UFW must be deleted")
                    self.assertTrue(inserted_quota, "VEXTUNNEL_QUOTA must be inserted at top of OUTPUT")
                    self.assertTrue(inserted_block, "VEXTUNNEL_BLOCK must be inserted at top of OUTPUT")

    def test_bidirectional_connmark_chains_initialization(self):
        """Test init_firewall_chains properly initializes mangle and input chains for bidirectional tracking."""
        from core.quota_manager import init_firewall_chains
        commands_run = []

        def fake_run(cmd, *args, **kwargs):
            commands_run.append(cmd)
            mock_res = mock.MagicMock()
            if cmd[:2] == ["iptables", "-S"]:
                mock_res.stdout = "-P OUTPUT ACCEPT\n"
            else:
                mock_res.stdout = ""
            mock_res.returncode = 1 if "-C" in cmd else 0
            return mock_res

        with mock.patch("os.name", "posix"):
            with mock.patch("os.geteuid", return_value=0, create=True):
                with mock.patch("subprocess.run", side_effect=fake_run):
                    res = init_firewall_chains()
                    self.assertTrue(res)

                    has_mangle_chain = any(c[:4] == ["iptables", "-t", "mangle", "-N"] and c[4] == "VEXTUNNEL_MANGLE_OUT" for c in commands_run)
                    has_prerouting_restore = any("PREROUTING" in c and "CONNMARK" in c and "--restore-mark" in c for c in commands_run)
                    has_input_quota = any("INPUT" in c and "VEXTUNNEL_QUOTA" in c for c in commands_run)

                    self.assertTrue(has_mangle_chain, "VEXTUNNEL_MANGLE_OUT chain must be created in mangle table")
                    self.assertTrue(has_prerouting_restore, "CONNMARK restore-mark must be installed in PREROUTING")
                    self.assertTrue(has_input_quota, "VEXTUNNEL_QUOTA must be jumped to from INPUT for ingress download accounting")

    def test_setup_accounting_rule_bidirectional(self):
        """Test setup_accounting_rule provisions MARK and CONNMARK rules in mangle and mark counter in filter."""
        from core.quota_manager import setup_accounting_rule
        commands_run = []

        def fake_run(cmd, *args, **kwargs):
            commands_run.append(cmd)
            mock_res = mock.MagicMock()
            mock_res.stdout = ""
            mock_res.returncode = 1 if "-C" in cmd else 0
            return mock_res

        with mock.patch("os.name", "posix"):
            with mock.patch("os.geteuid", return_value=0, create=True):
                with mock.patch("subprocess.run", side_effect=fake_run):
                    res = setup_accounting_rule(1003)
                    self.assertTrue(res)

                    has_mark = any("-t" in c and "mangle" in c and "MARK" in c and "--set-mark" in c and "1003" in c for c in commands_run)
                    has_save_mark = any("-t" in c and "mangle" in c and "CONNMARK" in c and "--save-mark" in c for c in commands_run)
                    has_quota_mark = any("VEXTUNNEL_QUOTA" in c and "-m" in c and "mark" in c and "1003" in c for c in commands_run)

                    self.assertTrue(has_mark, "Outbound packets must be marked with UID in mangle")
                    self.assertTrue(has_save_mark, "Mark must be saved to connection in mangle")
                    self.assertTrue(has_quota_mark, "Passive mark counter must be installed in VEXTUNNEL_QUOTA")

    def test_read_uid_bytes_mark_parsing(self):
        """Test read_uid_bytes correctly parses both hex and decimal iptables mark match lines."""
        from core.quota_manager import read_uid_bytes

        fake_output = (
            "Chain VEXTUNNEL_QUOTA (2 references)\n"
            " pkts bytes target prot opt in out source destination\n"
            "  100  1048576            all  --  *      *       0.0.0.0/0            0.0.0.0/0            mark match 0x3eb\n"
            "   50   524288            all  --  *      *       0.0.0.0/0            0.0.0.0/0            owner UID match 1002\n"
        )

        with mock.patch("os.name", "posix"):
            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.MagicMock(stdout=fake_output, returncode=0)
                bytes_1003 = read_uid_bytes(1003)
                self.assertEqual(bytes_1003, 1048576)

                bytes_1002 = read_uid_bytes(1002)
                self.assertEqual(bytes_1002, 524288)

                bytes_nonexistent = read_uid_bytes(9999)
                self.assertEqual(bytes_nonexistent, 0)

if __name__ == "__main__":
    unittest.main()
