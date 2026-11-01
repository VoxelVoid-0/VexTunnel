#!/usr/bin/env python3
"""
Unit & Security Tests for VexTunnel UserManager
"""

import unittest
import os
import tempfile
import datetime
from core.user_manager import UserManager

class TestUserManager(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary SQLite database for each test
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.mgr = UserManager(db_path=self.temp_db.name)

    def tearDown(self):
        # Clean up temporary Linux system users created during root tests
        for u in ["testuser1", "dupuser", "renewuser", "activeuser", "expireduser", "deluser", "authuser", "quotauser", "lockuser"]:
            try:
                self.mgr.delete_user(u)
            except Exception:
                pass

        # Clean up temporary database file
        if os.path.exists(self.temp_db.name):
            try:
                os.remove(self.temp_db.name)
            except OSError:
                pass
        for ext in ["-wal", "-shm"]:
            sidecar = self.temp_db.name + ext
            if os.path.exists(sidecar):
                try:
                    os.remove(sidecar)
                except OSError:
                    pass

    def test_database_initialization(self):
        """Verify SQLite table schema is properly created."""
        users = self.mgr.list_users()
        self.assertEqual(len(users), 0)

    def test_add_user_valid(self):
        """Verify normal alphanumeric username creation succeeds."""
        user = self.mgr.add_user("testuser1", "SecretPass123", days=30)
        self.assertEqual(user["username"], "testuser1")
        self.assertEqual(user["days"], 30)

        users = self.mgr.list_users()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["username"], "testuser1")
        self.assertEqual(users[0]["status"], "active")

    def test_add_user_command_injection_prevention(self):
        """Verify command injection attempts and invalid characters are strictly blocked."""
        malicious_inputs = [
            "user; rm -rf /",
            "admin && cat /etc/shadow",
            "test|sh",
            "user`whoami`",
            "user$(id)",
            "user name",
            "user@domain",
            "../etc/passwd",
            "user\nroot",
            "user' OR '1'='1"
        ]
        for bad_username in malicious_inputs:
            with self.subTest(username=bad_username):
                with self.assertRaises(ValueError):
                    self.mgr.add_user(bad_username, "SecretPass123", days=30)

    def test_add_duplicate_user(self):
        """Verify adding duplicate users raises an error."""
        self.mgr.add_user("dupuser", "SecretPass123", days=30)
        with self.assertRaises(Exception):
            self.mgr.add_user("dupuser", "SecretPass456", days=10)

    def test_delete_user(self):
        """Verify deleting an existing user removes them from SQLite."""
        self.mgr.add_user("deluser", "SecretPass123", days=30)
        self.assertEqual(len(self.mgr.list_users()), 1)

        result = self.mgr.delete_user("deluser")
        self.assertTrue(result)
        self.assertEqual(len(self.mgr.list_users()), 0)

        # Deleting non-existent user returns False
        self.assertFalse(self.mgr.delete_user("deluser"))

    def test_renew_user_active(self):
        """Verify renewing an active user extends their expiry date."""
        self.mgr.add_user("renewuser", "SecretPass123", days=10)
        initial_user = self.mgr.list_users()[0]
        initial_exp = datetime.datetime.strptime(initial_user["expires_at"], "%Y-%m-%d %H:%M:%S")

        res = self.mgr.renew_user("renewuser", days=15)
        self.assertIsNotNone(res)
        new_exp = datetime.datetime.strptime(res["new_expires_at"], "%Y-%m-%d %H:%M:%S")

        # New expiration must be approximately initial_exp + 15 days
        expected_diff = datetime.timedelta(days=15)
        self.assertAlmostEqual((new_exp - initial_exp).total_seconds(), expected_diff.total_seconds(), delta=5)

    def test_cleanup_expired_users(self):
        """Verify cleanup_expired locks expired accounts."""
        self.mgr.add_user("activeuser", "SecretPass123", days=10)
        self.mgr.add_user("expireduser", "SecretPass456", days=0)

        # Artificially set expireduser's date to the past in database
        past_date = (datetime.datetime.now() - datetime.timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
        with self.mgr._get_connection() as conn:
            conn.execute("UPDATE users SET expires_at = ? WHERE username = 'expireduser'", (past_date,))
            conn.commit()

        # Run cleanup
        cleaned_count = self.mgr.cleanup_expired()
        self.assertEqual(cleaned_count, 1)

        users = self.mgr.list_users()
        user_dict = {u["username"]: u["status"] for u in users}
        self.assertEqual(user_dict["activeuser"], "active")
        self.assertEqual(user_dict["expireduser"], "expired")

    def test_lock_unlock_user(self):
        """Verify lock_user and unlock_user toggle user status in database."""
        self.mgr.add_user("lockuser", "SecretPass123", days=30)
        self.assertEqual(self.mgr.list_users()[0]["status"], "active")

        # Lock user
        lock_res = self.mgr.lock_user("lockuser")
        self.assertTrue(lock_res)
        self.assertEqual(self.mgr.list_users()[0]["status"], "locked")

        # Unlock user
        unlock_res = self.mgr.unlock_user("lockuser")
        self.assertTrue(unlock_res)
        self.assertEqual(self.mgr.list_users()[0]["status"], "active")

if __name__ == "__main__":
    unittest.main()

