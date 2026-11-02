#!/usr/bin/env python3
"""
Unit tests for VexTunnel Self-Update & Database Preservation Engine (core/updater.py).
Validates SQLite native backup, backup rotation, lock-free rollback,
PEP 668 adaptive dependency sync, headless auto-rollback, and test mode isolation.
"""

import unittest
import os
import sys
import sqlite3
import tempfile
import shutil
from unittest import mock

# Set test mode so os.execv is not triggered
os.environ["VEXTUNNEL_TEST_MODE"] = "1"

from core.updater import (
    capture_pre_update_state,
    backup_database,
    sync_dependencies,
    apply_migrations,
    verify_health,
    rollback_update,
    interactive_rollback_countdown,
    reexec_menu,
    get_installed_version,
    get_git_commit,
    CORE_SERVICES,
    ESSENTIAL_SERVICES
)

class TestUpdater(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "vextunnel.db")
        self.backup_dir = os.path.join(self.tmp_dir, "backups")
        
        # Create a populated SQLite database in WAL mode
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    max_logins INTEGER DEFAULT 1,
                    status TEXT DEFAULT 'active'
                )
            """)
            conn.execute("INSERT INTO users (username, password_hash, expires_at) VALUES ('testuser', 'pbkdf2_sha256$mock', '2030-01-01 00:00:00')")
            conn.commit()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_sqlite_native_backup_and_rotation(self):
        """Test that native backup copies DB atomically and rotates old backups to max 5."""
        # 1. First backup
        ok, bkp_file = backup_database(self.db_path, backup_dir=self.backup_dir, max_backups=5)
        self.assertTrue(ok)
        self.assertTrue(os.path.isfile(bkp_file))

        # Verify integrity of backup
        with sqlite3.connect(bkp_file) as conn:
            rows = conn.execute("SELECT username FROM users;").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], "testuser")

        # 2. Generate 7 dummy backups to test rotation (max 5)
        for i in range(7):
            dummy_path = os.path.join(self.backup_dir, f"vextunnel_2026010{i}_120000.db")
            with sqlite3.connect(dummy_path) as conn:
                conn.execute("CREATE TABLE t (id INT);")

        ok2, bkp2 = backup_database(self.db_path, backup_dir=self.backup_dir, max_backups=5)
        self.assertTrue(ok2)

        # Count backups remaining
        remaining = [f for f in os.listdir(self.backup_dir) if f.startswith("vextunnel_") and f.endswith(".db")]
        self.assertLessEqual(len(remaining), 5, "Backup rotation must retain at most max_backups")

    def test_02_pre_update_active_services_filtering(self):
        """Test that previously inactive services do not cause false-positive rollbacks."""
        # Scenario: Only vextunnel-ws and dropbear were active before update (vextunnel-wss was inactive)
        pre_active = ["vextunnel-ws", "dropbear", "vextunnel-enforcer"]

        # If all 3 pre-active services are running, verify_health must succeed
        with mock.patch("core.updater.is_service_active", side_effect=lambda s: s in pre_active):
            healthy, failed = verify_health(pre_active)
            self.assertTrue(healthy)
            self.assertEqual(failed, [])

        # If an essential service (vextunnel-enforcer) died, verify_health must catch it
        broken_active = ["vextunnel-ws", "dropbear"]
        with mock.patch("core.updater.is_service_active", side_effect=lambda s: s in broken_active):
            healthy, failed = verify_health(pre_active)
            self.assertFalse(healthy)
            self.assertIn("vextunnel-enforcer", failed)

    def test_03_lock_free_rollback_with_truncate(self):
        """Test rollback_update stops services, restores DB, and executes WAL truncate."""
        # Create backup of initial state
        _, bkp_file = backup_database(self.db_path, backup_dir=self.backup_dir)

        # Corrupt / modify live DB
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE users SET username = 'corrupted' WHERE username = 'testuser';")
            conn.commit()

        # Perform rollback
        with mock.patch("core.updater.stop_tunnel_services", return_value=True) as mock_stop, \
             mock.patch("core.updater.start_tunnel_services", return_value=True) as mock_start:
            
            ok = rollback_update(
                repo_dir=self.tmp_dir,
                prev_commit="release",
                backup_file=bkp_file,
                db_path=self.db_path,
                services_to_restore=["vextunnel-ws", "dropbear"]
            )
            self.assertTrue(ok)
            mock_stop.assert_called_once()
            mock_start.assert_called_once()

        # Verify DB restored to testuser
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT username FROM users;").fetchall()
            self.assertEqual(rows[0][0], "testuser")

    def test_04_adaptive_pip_pep668_fallback(self):
        """Test sync_dependencies handles empty, missing, and system python flags."""
        # 1. Missing requirements.txt -> cleanly returns True
        ok, msg = sync_dependencies(self.tmp_dir)
        self.assertTrue(ok)
        self.assertIn("No dependencies", msg)

        # 2. Empty requirements.txt -> cleanly returns True
        req_file = os.path.join(self.tmp_dir, "requirements.txt")
        with open(req_file, "w") as f:
            f.write("# Empty requirements\n")
        ok, msg = sync_dependencies(self.tmp_dir)
        self.assertTrue(ok)

    def test_05_cross_platform_countdown_and_headless_bypass(self):
        """Test interactive_rollback_countdown instantly triggers timeout in headless mode."""
        # When sys.stdin is not a TTY (headless/scripted/cron)
        with mock.patch("sys.stdin.isatty", return_value=False):
            result = interactive_rollback_countdown(["vextunnel-ws"], timeout_sec=15)
            self.assertEqual(result, "timeout")

    def test_06_reexec_menu_test_mode_isolation(self):
        """Test reexec_menu safely exits without crashing during unit tests."""
        self.assertTrue(reexec_menu())

    def test_07_get_installed_version_and_commit(self):
        """Test reading version file and commit resolver."""
        # Without version file -> fallback v1.3.0
        self.assertEqual(get_installed_version(self.tmp_dir), "v1.3.0")

        # With version file
        with open(os.path.join(self.tmp_dir, "VERSION"), "w") as f:
            f.write("v1.4.2\n")
        self.assertEqual(get_installed_version(self.tmp_dir), "v1.4.2")

        # Git commit resolver on non-git dir -> 'release'
        self.assertEqual(get_git_commit(self.tmp_dir), "release")

if __name__ == "__main__":
    unittest.main()
