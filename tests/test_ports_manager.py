#!/usr/bin/env python3
"""
VexTunnel - Dynamic Ports Manager & 3x-ui Co-existence Unit Tests
Covers:
1. Environment file loading, defaults, and saving
2. Dual-stack IPv4/IPv6 port collision regex detection
3. Surgical firewall rules (UFW + Raw IPTables/ip6tables with ZERO blanket flushing)
4. Firewall co-existence retention (not deleting old port if occupied by 3x-ui/Xray)
5. Port validation and conflict avoidance
6. WSS enable/disable toggling and systemd interaction
7. Reset to default ports
8. Dynamic watchdog and doctor integration
"""

import unittest
import os
import sys
import tempfile
import re
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.ports_manager import (
    load_ports, save_ports, check_port_in_use, update_firewall_rules,
    set_port, toggle_wss, reset_default_ports, DEFAULT_PORTS
)
from core.watchdog import VexTunnelDoctor, ServiceWatchdog

class TestPortsManager(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.env_file = os.path.join(self.tmp_dir, "ports.env")

    def tearDown(self):
        if os.path.exists(self.env_file):
            try:
                os.remove(self.env_file)
            except OSError:
                pass
        try:
            os.rmdir(self.tmp_dir)
        except OSError:
            pass

    def test_01_load_default_ports(self):
        """Verify load_ports falls back to DEFAULT_PORTS when env file does not exist."""
        ports = load_ports(self.env_file)
        self.assertEqual(ports["WS_PORT"], 80)
        self.assertEqual(ports["WS_ALT_PORT"], 8880)
        self.assertEqual(ports["WSS_PORT"], 443)
        self.assertEqual(ports["DROPBEAR_PORT"], 109)
        self.assertEqual(ports["DROPBEAR_ALT_PORT"], 143)
        self.assertEqual(ports["UDPGW_PORT"], 7300)
        self.assertTrue(ports["WSS_ENABLED"])

    def test_02_save_and_reload_ports(self):
        """Verify saving customized ports persists correctly to file."""
        custom = {
            "WS_PORT": 8080,
            "WS_ALT_PORT": 8888,
            "WSS_PORT": 8443,
            "DROPBEAR_PORT": 110,
            "DROPBEAR_ALT_PORT": 144,
            "UDPGW_PORT": 7301,
            "WSS_ENABLED": False
        }
        ok = save_ports(custom, self.env_file)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(self.env_file))

        loaded = load_ports(self.env_file)
        self.assertEqual(loaded["WS_PORT"], 8080)
        self.assertEqual(loaded["WSS_PORT"], 8443)
        self.assertFalse(loaded["WSS_ENABLED"])

    def test_03_dual_stack_port_detection_regex(self):
        """Verify dual-stack IPv4 and IPv6 ss/netstat port matching regex."""
        # Simulated ss/netstat output lines
        sample_outputs = [
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"xray\",pid=1234,fd=3))",
            "LISTEN 0 128 [::]:443 [::]:* users:((\"xray\",pid=1234,fd=4))",
            "LISTEN 0 128 :::443 :::* users:((\"x-ui\",pid=5678,fd=5))",
            "tcp 0 0 127.0.0.1:443 0.0.0.0:* LISTEN 9999/python3",
            "tcp6 0 0 :::8443 :::* LISTEN 8888/vextunnel",
        ]

        port = 443
        pattern = re.compile(r'[:\]]' + str(port) + r'\s')

        # Test true positives
        for line in sample_outputs[:4]:
            self.assertIsNotNone(pattern.search(line), f"Failed to match port 443 in: {line}")

        # Test true negative (port 8443 should NOT match port 443 pattern)
        self.assertIsNone(pattern.search(sample_outputs[4]))

        # Test non-matching sub-ports (e.g. 4433, 1443)
        non_matching = "LISTEN 0 128 0.0.0.0:4433 0.0.0.0:* users:((\"nginx\",pid=100))"
        self.assertIsNone(pattern.search(non_matching))

    @patch("subprocess.run")
    def test_04_firewall_surgical_no_flush(self, mock_subproc):
        """Verify firewall updates NEVER execute iptables -F and update surgically."""
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Test UFW path
        with patch("shutil.which", side_effect=lambda cmd: "/usr/sbin/ufw" if cmd == "ufw" else None):
            with patch("core.ports_manager.check_port_in_use", return_value=(False, "")):
                ok = update_firewall_rules(new_port=8443, old_port=443, protocol="tcp")
                self.assertTrue(ok)

                # Ensure no iptables -F was ever called
                for call in mock_subproc.call_args_list:
                    cmd_args = call[0][0]
                    self.assertNotIn("-F", cmd_args, "CRITICAL SECURITY VIOLATION: Blanket flush detected!")

        # Test Raw IPTables path
        mock_subproc.reset_mock()
        with patch("shutil.which", side_effect=lambda cmd: "/sbin/iptables" if cmd in ("iptables", "ip6tables") else None):
            with patch("core.ports_manager.check_port_in_use", return_value=(False, "")):
                ok = update_firewall_rules(new_port=8443, old_port=443, protocol="tcp")
                self.assertTrue(ok)

                called_commands = [call[0][0] for call in mock_subproc.call_args_list]
                # Check for surgical insertion
                self.assertTrue(any("8443" in arg for cmd in called_commands for arg in cmd))
                # Ensure no -F
                for cmd in called_commands:
                    self.assertNotIn("-F", cmd, "Blanket flush detected in iptables path!")

    @patch("subprocess.run")
    def test_05_firewall_coexistence_retention(self, mock_subproc):
        """Verify old port is NOT deleted from firewall if occupied by 3x-ui / Xray."""
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with patch("shutil.which", side_effect=lambda cmd: "/usr/sbin/ufw" if cmd == "ufw" else None):
            # Simulate port 443 occupied by xray
            with patch("core.ports_manager.check_port_in_use", return_value=(True, "xray")):
                ok = update_firewall_rules(new_port=8443, old_port=443, protocol="tcp")
                self.assertTrue(ok)

                called_commands = [call[0][0] for call in mock_subproc.call_args_list]
                # Must NOT call 'ufw delete allow 443/tcp'
                for cmd in called_commands:
                    if "delete" in cmd:
                        self.fail(f"Firewall deleted port 443 while occupied by xray: {cmd}")

    def test_06_set_port_validation(self):
        """Verify set_port rejects invalid port numbers and internal port collisions."""
        # Port out of range
        ok, msg = set_port("WSS_PORT", 70000, env_file=self.env_file)
        self.assertFalse(ok)
        self.assertIn("Invalid port number", msg)

        ok, msg = set_port("WSS_PORT", 0, env_file=self.env_file)
        self.assertFalse(ok)

        # Port conflict with another VexTunnel service
        ok, msg = set_port("WSS_PORT", 80, env_file=self.env_file)
        self.assertFalse(ok)
        self.assertIn("already in use by WS_PORT", msg)

    @patch("core.ports_manager.update_firewall_rules", return_value=True)
    @patch("subprocess.run")
    def test_07_toggle_wss(self, mock_subproc, mock_fw):
        """Verify toggle_wss toggles WSS_ENABLED and manages vextunnel-wss systemd service."""
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Disable WSS
        ok, msg = toggle_wss(False, env_file=self.env_file)
        self.assertTrue(ok)
        ports = load_ports(self.env_file)
        self.assertFalse(ports["WSS_ENABLED"])

        # Enable WSS
        ok, msg = toggle_wss(True, env_file=self.env_file)
        self.assertTrue(ok)
        ports = load_ports(self.env_file)
        self.assertTrue(ports["WSS_ENABLED"])

    @patch("core.ports_manager.update_firewall_rules", return_value=True)
    def test_08_reset_default_ports(self, mock_fw):
        """Verify reset_default_ports restores defaults."""
        # Set a modified port first
        save_ports({"WSS_PORT": 9999, "WSS_ENABLED": False}, self.env_file)
        ok, msg = reset_default_ports(self.env_file)
        self.assertTrue(ok)

        ports = load_ports(self.env_file)
        self.assertEqual(ports["WSS_PORT"], 443)
        self.assertEqual(ports["WS_PORT"], 80)
        self.assertTrue(ports["WSS_ENABLED"])

    def test_09_watchdog_coexistence_reporting(self):
        """Verify Watchdog Doctor marks port 443 as disabled without failing health."""
        # When WSS is disabled
        with patch("core.watchdog.get_monitored_ports", return_value=([80, 109, 7300, 22], False, 443)):
            with patch("core.watchdog.VexTunnelDoctor.check_port_listener", return_value=True):
                res = VexTunnelDoctor.check_ports()
                self.assertTrue(res["ok"])
                self.assertEqual(res["ports"][443], "disabled (co-existence)")

        # When service healer inspects vextunnel-wss while WSS_ENABLED=False
        with patch("core.ports_manager.load_ports", return_value={"WSS_ENABLED": False}):
            watchdog = ServiceWatchdog()
            heal_res = watchdog.check_and_heal_service("vextunnel-wss")
            self.assertEqual(heal_res["status"], "disabled")
            self.assertFalse(heal_res["healed"])
            self.assertFalse(heal_res["circuit_breaker"])

if __name__ == "__main__":
    unittest.main()

