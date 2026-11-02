#!/usr/bin/env python3
"""
VexTunnel - Deep Hardening & Edge-Case Resilience Unit Tests
Covers:
1. Authoritative Expiry Gate in authenticate_user & list_users DB sync
2. Delta-based Bandwidth Quota Accounting across simulated iptables resets/reboots
3. Multi-daemon OpenSSH & Dropbear unified session tracking and termination
4. TUI safe_input KeyboardInterrupt cancellation and ANSI alignment
"""

import unittest
import os
import sys
import tempfile
import sqlite3
import datetime
import signal
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.user_manager import UserManager, hash_password
from core.quota_manager import sync_all_quotas, reset_user_quota, format_bytes, parse_bytes
from core.session_enforcer import get_active_user_sessions, enforce_concurrency_limits
from cli.menu import safe_input

class TestDeepHardening(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_deep.db")
        self.user_mgr = UserManager(self.db_path)
        for u in ["streamer", "resetme", "timetraveler", "ghostuser"]:
            try:
                self.user_mgr.delete_user(u)
            except Exception:
                pass

    def tearDown(self):
        for u in ["streamer", "resetme", "timetraveler", "ghostuser"]:
            try:
                self.user_mgr.delete_user(u)
            except Exception:
                pass
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass
        for ext in ["-wal", "-shm"]:
            sidecar = self.db_path + ext
            if os.path.exists(sidecar):
                try:
                    os.remove(sidecar)
                except OSError:
                    pass
        for f in os.listdir(self.tmp_dir):
            try:
                os.remove(os.path.join(self.tmp_dir, f))
            except OSError:
                pass
        try:
            os.rmdir(self.tmp_dir)
        except OSError:
            pass

    def test_01_authenticate_user_rejects_and_syncs_expired(self):
        """Verify authenticate_user rejects expired account immediately and commits expired status to DB."""
        # Create user expired 2 days ago
        expired_date = (datetime.datetime.now() - datetime.timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
        pwd_hash = hash_password("ValidPassword123")
        with self.user_mgr._get_connection() as conn:
            conn.execute("""
                INSERT INTO users (username, password_hash, expires_at, status)
                VALUES ('timetraveler', ?, ?, 'active')
            """, (pwd_hash, expired_date))
            conn.commit()

        # Attempt to authenticate
        auth_res = self.user_mgr.authenticate_user("timetraveler", "ValidPassword123")
        self.assertFalse(auth_res, "Expired user must NOT authenticate even if DB status was active!")

        # Verify DB status was authoritatively committed to 'expired'
        with self.user_mgr._get_connection() as conn:
            row = conn.execute("SELECT status FROM users WHERE username = 'timetraveler'").fetchone()
            self.assertEqual(row["status"], "expired", "DB status must be automatically updated to 'expired'")

    def test_02_list_users_syncs_expired_to_db(self):
        """Verify list_users dynamically detects expired users and commits expired status to DB."""
        expired_date = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        pwd_hash = hash_password("ValidPassword123")
        with self.user_mgr._get_connection() as conn:
            conn.execute("""
                INSERT INTO users (username, password_hash, expires_at, status)
                VALUES ('ghostuser', ?, ?, 'active')
            """, (pwd_hash, expired_date))
            conn.commit()

        users = self.user_mgr.list_users()
        user_entry = next(u for u in users if u["username"] == "ghostuser")
        self.assertEqual(user_entry["status"], "expired")

        # Verify DB row is committed
        with self.user_mgr._get_connection() as conn:
            row = conn.execute("SELECT status FROM users WHERE username = 'ghostuser'").fetchone()
            self.assertEqual(row["status"], "expired")

    def test_03_delta_bandwidth_accounting_across_reboots(self):
        """Verify delta-based quota manager correctly tracks usage across simulated VPS reboots and zeroed iptables."""
        # Create user with 100 MB quota (104,857,600 bytes)
        res = self.user_mgr.add_user("streamer", "ValidPassword123", days=30, quota_bytes=100 * 1024 * 1024)
        self.assertEqual(res["status"], "active")

        # Mock UID resolution to return UID 1500
        with patch("core.quota_manager.get_user_uid", return_value=1500), \
             patch("core.quota_manager.setup_accounting_rule", return_value=True), \
             patch("core.quota_manager.block_user_network") as mock_block, \
             patch("core.quota_manager.kill_user_sessions") as mock_kill:

            # Day 1: User downloads 40 MB
            with patch("core.quota_manager.read_uid_bytes", return_value=40 * 1024 * 1024):
                sync_all_quotas(self.db_path)

            with self.user_mgr._get_connection() as conn:
                u = conn.execute("SELECT used_bytes, last_counter_bytes, status FROM users WHERE username = 'streamer'").fetchone()
                self.assertEqual(u["used_bytes"], 40 * 1024 * 1024)
                self.assertEqual(u["last_counter_bytes"], 40 * 1024 * 1024)
                self.assertEqual(u["status"], "active")

            # Day 2: User downloads another 30 MB (iptables counter reaches 70 MB)
            with patch("core.quota_manager.read_uid_bytes", return_value=70 * 1024 * 1024):
                sync_all_quotas(self.db_path)

            with self.user_mgr._get_connection() as conn:
                u = conn.execute("SELECT used_bytes, last_counter_bytes, status FROM users WHERE username = 'streamer'").fetchone()
                self.assertEqual(u["used_bytes"], 70 * 1024 * 1024)
                self.assertEqual(u["last_counter_bytes"], 70 * 1024 * 1024)

            # SIMULATED VPS REBOOT: iptables counters are reset to 0!
            # After reboot, user reconnects and downloads 45 MB (iptables counter is now 45 MB < last_counter 70 MB)
            with patch("core.quota_manager.read_uid_bytes", return_value=45 * 1024 * 1024):
                sync_all_quotas(self.db_path)

            with self.user_mgr._get_connection() as conn:
                u = conn.execute("SELECT used_bytes, last_counter_bytes, status, quota_status FROM users WHERE username = 'streamer'").fetchone()
                # Total used should be 70 MB + 45 MB = 115 MB > 100 MB limit!
                self.assertEqual(u["used_bytes"], 115 * 1024 * 1024)
                self.assertEqual(u["last_counter_bytes"], 45 * 1024 * 1024)
                self.assertEqual(u["quota_status"], "quota_exceeded")
                self.assertEqual(u["status"], "quota_exceeded")

            # Verify network block and kill were triggered!
            mock_block.assert_called_with(1500)
            mock_kill.assert_called_with("streamer")

    def test_04_reset_user_quota_zeroes_watermark(self):
        """Verify resetting user quota zeroes both used_bytes and last_counter_bytes."""
        res = self.user_mgr.add_user("resetme", "ValidPassword123", days=30, quota_bytes=50 * 1024 * 1024)
        with self.user_mgr._get_connection() as conn:
            conn.execute("""
                UPDATE users SET used_bytes = 50000000, last_counter_bytes = 50000000, status = 'quota_exceeded', quota_status = 'quota_exceeded'
                WHERE username = 'resetme'
            """)
            conn.commit()

        with patch("core.quota_manager.get_user_uid", return_value=1501), \
             patch("core.quota_manager.unblock_user_network") as mock_unblock:
            success = reset_user_quota("resetme", self.db_path)
            self.assertTrue(success)
            mock_unblock.assert_called_with(1501)

        with self.user_mgr._get_connection() as conn:
            u = conn.execute("SELECT used_bytes, last_counter_bytes, status, quota_status FROM users WHERE username = 'resetme'").fetchone()
            self.assertEqual(u["used_bytes"], 0)
            self.assertEqual(u["last_counter_bytes"], 0)
            self.assertEqual(u["status"], "active")
            self.assertEqual(u["quota_status"], "active")

    def test_05_unified_session_detection_dropbear_and_openssh(self):
        """Verify get_active_user_sessions detects both Dropbear and OpenSSH (sshd-session) sessions."""
        mock_ps_output = (
            "USER       PID COMM            ARGS\n"
            "root      1001 sshd            sshd: /usr/sbin/sshd -D\n"
            "root      1002 dropbear        /usr/sbin/dropbear -EF -p 143\n"
            "alice     2001 dropbear        /usr/sbin/dropbear -EF\n"
            "alice     2002 dropbear        /usr/sbin/dropbear -EF\n"
            "bob       3001 sshd-session    sshd-session: bob@notty\n"
            "charlie   4001 sshd            sshd: charlie@pts/1\n"
            "daemon    5001 sshd            sshd: daemon\n"
        )
        mock_run = MagicMock()
        mock_run.stdout = mock_ps_output
        mock_run.returncode = 0

        with patch("os.name", "posix"), patch("subprocess.run", return_value=mock_run):
            sessions = get_active_user_sessions()

            self.assertIn("alice", sessions)
            self.assertEqual(sessions["alice"], [2001, 2002], "Dropbear sessions must be captured")

            self.assertIn("bob", sessions)
            self.assertEqual(sessions["bob"], [3001], "OpenSSH non-tty tunnel sessions must be captured")

            self.assertIn("charlie", sessions)
            self.assertEqual(sessions["charlie"], [4001], "OpenSSH interactive sessions must be captured")

            self.assertNotIn("root", sessions, "Root daemon processes must be ignored")
            self.assertNotIn("daemon", sessions, "System daemon users must be ignored")

    def test_06_safe_input_handles_keyboard_interrupt(self):
        """Verify safe_input returns '0' when KeyboardInterrupt is raised."""
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            res = safe_input("Test Prompt: ")
            self.assertEqual(res, "0", "KeyboardInterrupt must be safely trapped and return '0'")

    def test_07_enforce_concurrency_terminates_unregistered_rogue_accounts(self):
        """Verify enforce_concurrency_limits terminates unauthorized/orphaned accounts not in database."""
        # Database only has user 'activeuser'
        self.user_mgr.add_user("activeuser", "ValidPass123", days=30, max_logins=2)

        # Process table contains 'activeuser' (1 session) and 'rogueuser' (2 sessions)
        mock_active = {
            "activeuser": [10001],
            "rogueuser": [20001, 20002]
        }

        with patch("core.session_enforcer.get_active_user_sessions", return_value=mock_active), \
             patch("core.session_enforcer.sync_all_quotas"), \
             patch("os.kill") as mock_kill:
            killed = enforce_concurrency_limits(self.db_path)

            # rogueuser sessions must be terminated
            self.assertEqual(killed, 2, "Both sessions of unregistered rogueuser must be killed")
            mock_kill.assert_any_call(20001, signal.SIGTERM)
            mock_kill.assert_any_call(20002, signal.SIGTERM)

    def test_08_sync_orphaned_system_users(self):
        """Verify sync_orphaned_system_users purges Linux accounts with restricted shells not present in DB."""
        # DB has 'minsara'
        self.user_mgr.add_user("minsara", "ValidPass123", days=30)

        # Mock pwd entries: minsara (registered), leonvpn (orphaned), ubuntu (admin), root (system)
        mock_entry_minsara = MagicMock(pw_name="minsara", pw_uid=1001, pw_shell="/bin/false")
        mock_entry_leonvpn = MagicMock(pw_name="leonvpn", pw_uid=1002, pw_shell="/bin/false")
        mock_entry_ubuntu = MagicMock(pw_name="ubuntu", pw_uid=1000, pw_shell="/bin/bash")
        mock_entry_root = MagicMock(pw_name="root", pw_uid=0, pw_shell="/bin/bash")

        with patch("os.name", "posix"), \
             patch("os.geteuid", return_value=0), \
             patch("pwd.getpwall", return_value=[mock_entry_minsara, mock_entry_leonvpn, mock_entry_ubuntu, mock_entry_root]), \
             patch("subprocess.run") as mock_subproc:
            cleaned = self.user_mgr.sync_orphaned_system_users()
            self.assertEqual(cleaned, 1)
            mock_subproc.assert_called_with(["userdel", "-f", "leonvpn"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    unittest.main()
