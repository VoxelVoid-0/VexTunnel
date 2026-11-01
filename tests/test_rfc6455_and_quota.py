#!/usr/bin/env python3
"""
Unit tests for RFC 6455 dynamic WebSocket handshake calculations,
clean database migration without legacy password columns,
and kernel-level quota management.
"""

import unittest
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
        for u in ["testalice", "legacybob", "authuser", "quotauser"]:
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
        self.assertEqual(parse_bytes("500M"), 500 * 1024 * 1024)
        self.assertEqual(parse_bytes("50G"), 50 * 1024 * 1024 * 1024)
        self.assertEqual(parse_bytes("2TB"), 2 * 1024**4)

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

if __name__ == "__main__":
    unittest.main()
