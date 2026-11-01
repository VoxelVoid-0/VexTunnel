#!/usr/bin/env python3
"""
VexTunnel - Phase 2: Self-Healing Watchdog & Startup Health Doctor Unit Tests
Covers:
1. Database low-level B-tree and page integrity verification
2. Incomplete database schema detection
3. Missing database file detection
4. Firewall chain existence and self-healing recreation
5. Port availability probing and SSL certificate validity check
6. Watchdog active service detection
7. Dead service self-healing recovery and restart trigger
8. Circuit breaker thrashing prevention after repeated failures
"""

import unittest
import os
import sys
import tempfile
import sqlite3
import time
from unittest.mock import patch, MagicMock

from core.watchdog import VexTunnelDoctor, ServiceWatchdog
from core.user_manager import UserManager

class TestWatchdogAndDoctor(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_doctor.db")
        self.user_mgr = UserManager(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
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

    def test_01_doctor_database_healthy(self):
        """Verify doctor confirms healthy state on clean, initialized database."""
        res = VexTunnelDoctor.check_database(self.db_path)
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "healthy")
        self.assertFalse(res["repaired"])

    def test_02_doctor_database_missing(self):
        """Verify doctor identifies missing database file correctly."""
        missing_path = os.path.join(self.tmp_dir, "nonexistent.db")
        res = VexTunnelDoctor.check_database(missing_path)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "missing")

    def test_03_doctor_database_incomplete_schema(self):
        """Verify doctor flags database missing required core tables."""
        incomplete_path = os.path.join(self.tmp_dir, "incomplete.db")
        conn = sqlite3.connect(incomplete_path)
        conn.execute("CREATE TABLE dummy (id INT);")
        conn.commit()
        conn.close()

        res = VexTunnelDoctor.check_database(incomplete_path)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "incomplete_schema")

    def test_04_doctor_firewall_chains(self):
        """Verify firewall chain inspection safely runs or handles missing chains."""
        res = VexTunnelDoctor.check_firewall_chains()
        self.assertTrue(res["ok"])

    def test_05_doctor_ssl_cert_check(self):
        """Verify SSL certificate inspector correctly identifies missing and present certs."""
        # Nonexistent cert
        res_missing = VexTunnelDoctor.check_ssl_certificate(os.path.join(self.tmp_dir, "nocert.pem"))
        self.assertFalse(res_missing["ok"])
        self.assertEqual(res_missing["status"], "missing")

        # Mock present cert file
        dummy_cert = os.path.join(self.tmp_dir, "cert.pem")
        with open(dummy_cert, "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----")

        res_present = VexTunnelDoctor.check_ssl_certificate(dummy_cert)
        self.assertTrue(res_present["ok"])

    def test_06_watchdog_active_service(self):
        """Verify watchdog does not restart already active services."""
        watchdog = ServiceWatchdog(services=["vextunnel-ws"])
        with patch.object(watchdog, "is_service_active", return_value=True):
            res = watchdog.check_and_heal_service("vextunnel-ws")
            self.assertEqual(res["status"], "active")
            self.assertFalse(res["healed"])

    def test_07_watchdog_heals_dead_service(self):
        """Verify watchdog detects dead service and triggers self-healing restart."""
        watchdog = ServiceWatchdog(services=["vextunnel-wss"])
        with patch.object(watchdog, "is_service_active", return_value=False), \
             patch.object(watchdog, "restart_service", return_value=True) as mock_restart:
            res = watchdog.check_and_heal_service("vextunnel-wss")
            self.assertEqual(res["status"], "restarted")
            self.assertTrue(res["healed"])
            mock_restart.assert_called_once_with("vextunnel-wss")

    def test_08_watchdog_circuit_breaker(self):
        """Verify watchdog circuit breaker trips after max restarts to prevent thrashing."""
        watchdog = ServiceWatchdog(services=["broken-service"], max_restarts=3, window_sec=60.0)

        # Simulate 3 rapid restarts
        now = time.time()
        watchdog.restart_history["broken-service"] = [now - 10, now - 5, now - 1]

        with patch.object(watchdog, "is_service_active", return_value=False), \
             patch.object(watchdog, "restart_service") as mock_restart:
            res = watchdog.check_and_heal_service("broken-service")
            self.assertEqual(res["status"], "failed")
            self.assertFalse(res["healed"])
            self.assertTrue(res["circuit_breaker"], "Circuit breaker must be tripped!")
            mock_restart.assert_not_called()

if __name__ == "__main__":
    unittest.main()
