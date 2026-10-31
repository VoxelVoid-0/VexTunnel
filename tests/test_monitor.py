#!/usr/bin/env python3
"""
Unit Tests for VexTunnel System & Service Monitor
"""

import unittest
from core.monitor import get_system_stats

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

if __name__ == "__main__":
    unittest.main()
