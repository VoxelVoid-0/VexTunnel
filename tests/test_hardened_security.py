#!/usr/bin/env python3
"""
Unit Tests for VexTunnel v1.2 Production Hardened Security & DB Features
"""

import unittest
import tempfile
import os
import sqlite3
from core.user_manager import UserManager, hash_password, verify_password

class TestHardenedSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.mgr = UserManager(db_path=self.temp_db.name)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            try:
                os.remove(self.temp_db.name)
            except OSError:
                pass
        wal_file = self.temp_db.name + "-wal"
        shm_file = self.temp_db.name + "-shm"
        for extra in (wal_file, shm_file):
            if os.path.exists(extra):
                try:
                    os.remove(extra)
                except OSError:
                    pass

    def test_pbkdf2_password_hashing(self):
        """Verify PBKDF2-SHA256 password hashing and constant-time verification."""
        password = "SuperSecretPassword123"
        hashed = hash_password(password)

        self.assertTrue(hashed.startswith("pbkdf2_sha256$"))
        self.assertEqual(len(hashed.split("$")), 3)

        # Verification tests
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("WrongPassword123", hashed))
        self.assertFalse(verify_password("", hashed))
        self.assertFalse(verify_password(password, "invalid_hash_string"))

    def test_unique_salts_per_hash(self):
        """Verify two hashes of the same password produce different digests due to random salt."""
        pwd = "IdenticalPassword123"
        hash1 = hash_password(pwd)
        hash2 = hash_password(pwd)
        self.assertNotEqual(hash1, hash2)
        self.assertTrue(verify_password(pwd, hash1))
        self.assertTrue(verify_password(pwd, hash2))

    def test_password_policy_enforcement(self):
        """Verify minimum length 8 and rejection of control characters."""
        # Too short (<8)
        with self.assertRaises(ValueError):
            self.mgr.add_user("testuser", "short", days=30)

        # Contains newline or null byte
        with self.assertRaises(ValueError):
            self.mgr.add_user("testuser", "pass\nwithnewline", days=30)
        with self.assertRaises(ValueError):
            self.mgr.add_user("testuser", "pass\rwithcarriage", days=30)
        with self.assertRaises(ValueError):
            self.mgr.add_user("testuser", "pass\x00withnull", days=30)

    def test_sqlite_wal_and_pragmas(self):
        """Verify SQLite WAL mode and busy timeout pragmas are set."""
        with self.mgr._get_connection() as conn:
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual(journal_mode.lower(), "wal")

            busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
            self.assertEqual(busy_timeout, 5000)

    def test_change_password(self):
        """Verify changing password updates hash in database."""
        self.mgr.add_user("pwdchangeuser", "InitialPass123", days=30)
        user_initial = self.mgr.list_users()[0]
        initial_hash = user_initial["password_hash"]

        # Change password
        success = self.mgr.change_password("pwdchangeuser", "NewSuperPass456")
        self.assertTrue(success)

        user_updated = self.mgr.list_users()[0]
        new_hash = user_updated["password_hash"]
        self.assertNotEqual(initial_hash, new_hash)
        self.assertTrue(verify_password("NewSuperPass456", new_hash))
        self.assertFalse(verify_password("InitialPass123", new_hash))

if __name__ == "__main__":
    unittest.main()
