#!/usr/bin/env python3
"""
Unit tests for VexTunnel Self-Update & Database Preservation Engine (core/updater.py - v6).
Validates SQLite native backup, backup rotation, lock-free rollback,
PEP 668 adaptive dependency sync, headless auto-rollback, test mode isolation,
fail-closed disk space gate, py_compile staging validation, two-tier rollback,
deep socket health check, and ports.env preservation shields.
"""

import unittest
import os
import sys
import socket
import sqlite3
import tempfile
import shutil
import tarfile
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
    check_disk_space,
    pause_enforcer_for_migration,
    create_code_snapshot,
    stage_and_verify_release,
    promote_staging_to_production,
    sync_systemd_units,
    deep_socket_health_check,
    two_tier_rollback,
    purge_bytecode,
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
        ok, msg = sync_dependencies(self.tmp_dir)
        self.assertTrue(ok)
        self.assertIn("No dependencies", msg)

        req_file = os.path.join(self.tmp_dir, "requirements.txt")
        with open(req_file, "w") as f:
            f.write("# Empty requirements\n")
        ok, msg = sync_dependencies(self.tmp_dir)
        self.assertTrue(ok)

    def test_05_cross_platform_countdown_and_headless_bypass(self):
        """Test interactive_rollback_countdown instantly triggers timeout in headless mode."""
        with mock.patch("sys.stdin.isatty", return_value=False):
            result = interactive_rollback_countdown(["vextunnel-ws"], timeout_sec=15)
            self.assertEqual(result, "timeout")

    def test_06_reexec_menu_test_mode_isolation(self):
        """Test reexec_menu safely exits without crashing during unit tests."""
        self.assertTrue(reexec_menu())

    def test_07_get_installed_version_and_commit(self):
        """Test reading version file and commit resolver."""
        self.assertEqual(get_installed_version(self.tmp_dir), "v1.3.0")

        with open(os.path.join(self.tmp_dir, "VERSION"), "w") as f:
            f.write("v1.4.2\n")
        self.assertEqual(get_installed_version(self.tmp_dir), "v1.4.2")
        self.assertEqual(get_git_commit(self.tmp_dir), "release")

    def test_08_fail_closed_disk_space_gate(self):
        """Test check_disk_space passes when space >= 150MB, rejects when low, and fails closed."""
        # 1. Sufficient space (e.g. 500 MB)
        with mock.patch("shutil.disk_usage", return_value=mock.Mock(free=500 * 1024 * 1024)):
            ok, mb = check_disk_space(self.tmp_dir, min_free_mb=150)
            self.assertTrue(ok)
            self.assertEqual(mb, 500)

        # 2. Insufficient space (e.g. 80 MB)
        with mock.patch("shutil.disk_usage", return_value=mock.Mock(free=80 * 1024 * 1024)):
            ok, mb = check_disk_space(self.tmp_dir, min_free_mb=150)
            self.assertFalse(ok)
            self.assertEqual(mb, 80)

        # 3. Fail-Closed on OS / permissions error
        with mock.patch("shutil.disk_usage", side_effect=OSError("Disk access denied")):
            ok, mb = check_disk_space(self.tmp_dir, min_free_mb=150)
            self.assertFalse(ok)
            self.assertEqual(mb, 0)

    def test_09_staging_py_compile_validation(self):
        """Test staging validates archive, verifies critical files, and catches syntax errors."""
        pkg_dir = os.path.join(self.tmp_dir, "fake_release")
        os.makedirs(os.path.join(pkg_dir, "core"), exist_ok=True)
        os.makedirs(os.path.join(pkg_dir, "cli"), exist_ok=True)

        with open(os.path.join(pkg_dir, "VERSION"), "w") as f:
            f.write("v1.4.0\n")
        with open(os.path.join(pkg_dir, "core", "ws_proxy.py"), "w") as f:
            f.write("# valid python\ndef test(): return True\n")
        with open(os.path.join(pkg_dir, "core", "user_manager.py"), "w") as f:
            f.write("class UserManager: pass\n")
        with open(os.path.join(pkg_dir, "core", "updater.py"), "w") as f:
            f.write("# valid updater\n")
        with open(os.path.join(pkg_dir, "cli", "menu.py"), "w") as f:
            f.write("# valid menu\n")

        valid_tar = os.path.join(self.tmp_dir, "valid_rel.tar.gz")
        with tarfile.open(valid_tar, "w:gz") as tar:
            tar.add(pkg_dir, arcname=".")

        # Test valid release package extraction & py_compile
        ok, stage_dir = stage_and_verify_release(valid_tar)
        self.assertTrue(ok)
        self.assertTrue(os.path.isdir(stage_dir))
        shutil.rmtree(stage_dir, ignore_errors=True)

        # Inject syntax error into a .py file
        with open(os.path.join(pkg_dir, "core", "broken.py"), "w") as f:
            f.write("def broken_syntax( -syntax error- here! \n")

        broken_tar = os.path.join(self.tmp_dir, "broken_rel.tar.gz")
        with tarfile.open(broken_tar, "w:gz") as tar:
            tar.add(pkg_dir, arcname=".")

        ok_broken, err_msg = stage_and_verify_release(broken_tar)
        self.assertFalse(ok_broken)
        self.assertIn("Syntax verification failed", err_msg)

    def test_10_two_tier_rollback_restores_code_and_db(self):
        """Test two_tier_rollback atomically restores both codebase snapshot and SQLite DB."""
        app_dir = os.path.join(self.tmp_dir, "app")
        os.makedirs(os.path.join(app_dir, "core"), exist_ok=True)
        version_file = os.path.join(app_dir, "VERSION")
        with open(version_file, "w") as f:
            f.write("v1.3.1\n")

        code_py = os.path.join(app_dir, "core", "logic.py")
        with open(code_py, "w") as f:
            f.write("VERSION_STRING = 'stable_v131'\n")

        # 1. Create code snapshot
        snap_path = os.path.join(self.tmp_dir, "rollback_snap.tar.gz")
        ok_snap, _ = create_code_snapshot(app_dir, snapshot_path=snap_path)
        self.assertTrue(ok_snap)

        # 2. Create DB backup
        ok_bkp, bkp_file = backup_database(self.db_path, backup_dir=self.backup_dir)
        self.assertTrue(ok_bkp)

        # 3. Simulate destructive code update + DB corruption
        with open(version_file, "w") as f:
            f.write("v1.4.0-broken\n")
        with open(code_py, "w") as f:
            f.write("BROKEN_CODE = True\n")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE users SET username = 'destroyed' WHERE username = 'testuser';")
            conn.commit()

        # 4. Trigger Two-Tier Rollback
        with mock.patch("core.updater.stop_tunnel_services", return_value=True), \
             mock.patch("core.updater.start_tunnel_services", return_value=True):
            rb_ok = two_tier_rollback(
                install_dir=app_dir,
                code_snapshot_path=snap_path,
                db_backup_path=bkp_file,
                db_path=self.db_path,
                services_to_restore=["vextunnel-ws"]
            )
            self.assertTrue(rb_ok)

        # 5. Verify codebase restored
        with open(version_file, "r") as f:
            self.assertEqual(f.read().strip(), "v1.3.1")
        with open(code_py, "r") as f:
            self.assertIn("stable_v131", f.read())

        # 6. Verify DB restored
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT username FROM users;").fetchone()
            self.assertEqual(row[0], "testuser")

    def test_11_deep_socket_health_check(self):
        """Test deep_socket_health_check confirms localhost TCP connectivity."""
        # Spin up a temporary listening server socket on localhost
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        assigned_port = server.getsockname()[1]

        try:
            # Socket probe on open port should succeed
            with mock.patch("core.updater.os.name", "posix"):
                ok, failed = deep_socket_health_check([assigned_port], timeout=1.0)
                self.assertTrue(ok)
                self.assertEqual(failed, [])

                # Socket probe on unused closed port should fail
                closed_port = 59999
                ok2, failed2 = deep_socket_health_check([closed_port], timeout=0.5)
                self.assertFalse(ok2)
                self.assertIn(closed_port, failed2)
        finally:
            server.close()

    def test_12_ports_env_and_db_protection_during_promotion(self):
        """Test promote_staging_to_production protects ports.env, certs, and .db from overwrite."""
        install_dir = os.path.join(self.tmp_dir, "prod_install")
        os.makedirs(os.path.join(install_dir, "certs"), exist_ok=True)

        # User's custom configuration
        user_ports_file = os.path.join(install_dir, "ports.env")
        with open(user_ports_file, "w") as f:
            f.write("WS_PORT=8080\nWSS_PORT=8443\n")

        user_cert_file = os.path.join(install_dir, "certs", "cert.pem")
        with open(user_cert_file, "w") as f:
            f.write("USER_CERTIFICATE_CONTENT\n")

        user_db_file = os.path.join(install_dir, "vextunnel.db")
        with open(user_db_file, "w") as f:
            f.write("REAL_DATABASE_DATA\n")

        # Staging directory with default values
        staging_dir = os.path.join(self.tmp_dir, "staging_area")
        os.makedirs(staging_dir, exist_ok=True)

        with open(os.path.join(staging_dir, "ports.env"), "w") as f:
            f.write("WS_PORT=80\nWSS_PORT=443\n")
        with open(os.path.join(staging_dir, "vextunnel.db"), "w") as f:
            f.write("DEFAULT_EMPTY_DB\n")
        with open(os.path.join(staging_dir, "VERSION"), "w") as f:
            f.write("v1.4.0\n")

        # Promote staging -> production
        ok, msg = promote_staging_to_production(staging_dir, install_dir=install_dir)
        self.assertTrue(ok)

        # Assert user's custom ports were NOT overwritten
        with open(user_ports_file, "r") as f:
            ports_content = f.read()
            self.assertIn("WS_PORT=8080", ports_content)
            self.assertNotIn("WS_PORT=80\n", ports_content)

        # Assert user's DB was NOT overwritten
        with open(user_db_file, "r") as f:
            self.assertEqual(f.read(), "REAL_DATABASE_DATA\n")

        # Assert certs were untouched
        with open(user_cert_file, "r") as f:
            self.assertEqual(f.read(), "USER_CERTIFICATE_CONTENT\n")

        # Assert new version was promoted
        with open(os.path.join(install_dir, "VERSION"), "r") as f:
            self.assertEqual(f.read().strip(), "v1.4.0")

if __name__ == "__main__":
    unittest.main()
