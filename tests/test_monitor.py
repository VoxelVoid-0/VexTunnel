#!/usr/bin/env python3
"""
Unit Tests for VexTunnel System & Service Monitor
"""

import unittest
from unittest.mock import patch, MagicMock
from core.monitor import get_system_stats, get_online_users

class TestMonitor(unittest.TestCase):
    def test_get_system_stats_structure(self):
        """Verify get_system_stats returns required system telemetry fields."""
        stats = get_system_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn("os", stats)
        self.assertIn("cpu", stats)
        self.assertIn("ram_percent", stats)
        self.assertIn("disk_percent", stats)
        self.assertIn("ram_used_mb", stats)
        self.assertIn("ram_total_mb", stats)

    def test_disk_percent_range(self):
        """Verify disk percentage is within 0.0% and 100.0%."""
        stats = get_system_stats()
        self.assertGreaterEqual(stats["disk_percent"], 0.0)
        self.assertLessEqual(stats["disk_percent"], 100.0)

    def test_get_online_users_excludes_system_and_captures_dropbear(self):
        """Verify get_online_users excludes root and system users, and correctly captures Dropbear processes with -p args."""
        mock_ps = (
            "USER       PID COMM            ARGS\n"
            "root      1001 sshd            sshd: /usr/sbin/sshd -D\n"
            "root      1002 dropbear        /usr/sbin/dropbear -EF -p 143 -W 65536 -p 109\n"
            "ubuntu    2001 sshd            sshd: ubuntu@pts/0\n"
            "minsara   3001 dropbear        /usr/sbin/dropbear -EF -p 143 -W 65536 -p 109 -2 10\n"
            "vpnuser   4001 sshd-session    sshd-session: vpnuser@notty\n"
        )
        mock_res = MagicMock()
        mock_res.stdout = mock_ps
        mock_res.returncode = 0

        with patch("os.name", "posix"), patch("subprocess.run", return_value=mock_res), patch("os.path.exists", return_value=False):
            online = get_online_users()
            users = [o["user"] for o in online]

            # Root and cloud administrator must be excluded
            self.assertNotIn("root", users, "Root must never be listed as an online VPN user")
            self.assertNotIn("ubuntu", users, "Cloud admin ubuntu must not be listed as an online VPN user")

            # VPN users must be captured
            self.assertIn("minsara", users, "Dropbear child process with -p args must be captured")
            self.assertIn("vpnuser", users, "OpenSSH non-tty tunnel user must be captured")

    def test_get_online_users_filters_with_database(self):
        """Verify get_online_users strictly filters to registered DB users when database is present."""
        mock_ps = (
            "USER       PID COMM            ARGS\n"
            "minsara   3001 dropbear        /usr/sbin/dropbear -EF -p 143 -W 65536 -p 109 -2 10\n"
            "unregistered 4001 sshd-session sshd-session: unregistered@notty\n"
        )
        mock_res = MagicMock()
        mock_res.stdout = mock_ps
        mock_res.returncode = 0

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = [("minsara",)]

        with patch("os.name", "posix"), \
             patch("subprocess.run", return_value=mock_res), \
             patch("os.path.exists", return_value=True), \
             patch("sqlite3.connect", return_value=mock_conn):
            online = get_online_users(db_path="/mock/vextunnel.db")
            users = [o["user"] for o in online]
            self.assertIn("minsara", users)
            self.assertNotIn("unregistered", users)

if __name__ == "__main__":
    unittest.main()

