#!/usr/bin/env python3
"""
Unit and Integration Tests for VexTunnel Subscription Web Portal & Cloudflare Tunnel
Author: VoxelVoid-0
License: GPL-3.0
"""

import unittest
import tempfile
import os
import shutil
import sqlite3
import datetime
import urllib.request
import urllib.error
import json
import threading
import socket
import re
from unittest.mock import patch

from core.user_manager import UserManager, hash_password
from core.sub_server import (
    ThreadedVexSubServer,
    VexSubRequestHandler,
    ThreadSafeRateLimiter,
    TOKEN_REGEX,
    format_bytes
)
import core.cf_tunnel as cf_tunnel

def find_free_port() -> int:
    """Find a random unused TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

class TestSubServerAndTokens(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "vextunnel_test.db")
        self.mgr = UserManager(db_path=self.db_path)

        # Create active test user
        self.user_active = self.mgr.add_user(
            username="activeuser",
            password="Password123!",
            days=30,
            quota_bytes=10 * 1024 * 1024 * 1024 # 10 GB
        )

        # Create expired test user
        self.user_expired = self.mgr.add_user(
            username="expireduser",
            password="Password123!",
            days=1,
            quota_bytes=5 * 1024 * 1024 * 1024
        )
        # Manually backdate expiry in DB
        with self.mgr._get_connection() as conn:
            past_date = (datetime.datetime.now() - datetime.timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("UPDATE users SET expires_at = ?, status = 'expired' WHERE username = 'expireduser'", (past_date,))
            conn.commit()

        # Create quota exceeded user
        self.user_quota = self.mgr.add_user(
            username="quotauser",
            password="Password123!",
            days=30,
            quota_bytes=1024 * 1024 * 100 # 100 MB
        )
        with self.mgr._get_connection() as conn:
            conn.execute("UPDATE users SET used_bytes = 1024 * 1024 * 150 WHERE username = 'quotauser'")
            conn.commit()

        # Start live localhost sub server on random free port
        self.server_port = find_free_port()
        self.server = ThreadedVexSubServer(("127.0.0.1", self.server_port), VexSubRequestHandler)
        self.server.db_path = self.db_path
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def tearDown(self):
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_token_generation_and_schema(self):
        """Verify sub_token is automatically generated as a 32-char hex string upon user creation."""
        token = self.user_active.get("sub_token")
        self.assertIsNotNone(token)
        self.assertEqual(len(token), 32)
        self.assertTrue(TOKEN_REGEX.fullmatch(token))

        # Check lookup by token
        fetched = self.mgr.get_user_by_token(token)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["username"], "activeuser")
        self.assertEqual(fetched["status"], "active")
        self.assertGreaterEqual(fetched["remaining_days"], 29)

    def test_02_regenerate_token(self):
        """Verify token regeneration creates a new unique 32-char token and invalidates old token."""
        old_token = self.user_active["sub_token"]
        new_token = self.mgr.regenerate_sub_token("activeuser")
        self.assertNotEqual(old_token, new_token)
        self.assertEqual(len(new_token), 32)
        self.assertTrue(TOKEN_REGEX.fullmatch(new_token))

        # Old token should now return None
        self.assertIsNone(self.mgr.get_user_by_token(old_token))
        # New token should return activeuser
        fetched = self.mgr.get_user_by_token(new_token)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["username"], "activeuser")

    def test_03_regex_validation(self):
        """Verify TOKEN_REGEX strictly accepts 32-char lowercase hex and rejects invalid patterns."""
        self.assertTrue(TOKEN_REGEX.fullmatch("a" * 32))
        self.assertTrue(TOKEN_REGEX.fullmatch("0123456789abcdef0123456789abcdef"))

        # Rejections
        self.assertIsNone(TOKEN_REGEX.fullmatch("A" * 32)) # Uppercase
        self.assertIsNone(TOKEN_REGEX.fullmatch("a" * 31)) # Too short
        self.assertIsNone(TOKEN_REGEX.fullmatch("a" * 33)) # Too long
        self.assertIsNone(TOKEN_REGEX.fullmatch("a" * 31 + "g")) # Non-hex char 'g'
        self.assertIsNone(TOKEN_REGEX.fullmatch("'; DROP TABLE users; --")) # SQL injection attempt
        self.assertIsNone(TOKEN_REGEX.fullmatch("../../../etc/passwd")) # Path traversal attempt

    def test_04_health_endpoint(self):
        """Verify GET /health returns 200 OK with expected JSON payload."""
        url = f"http://127.0.0.1:{self.server_port}/health"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["service"], "vextunnel-sub")

    def test_05_html_sub_card_active_user(self):
        """Verify GET /sub/<token> renders valid 3x-ui dark HTML with active metrics."""
        token = self.user_active["sub_token"]
        url = f"http://127.0.0.1:{self.server_port}/sub/{token}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            html = resp.read().decode("utf-8")
            self.assertIn("activeuser", html)
            self.assertIn("ACTIVE", html)
            self.assertIn("Traffic & Quota", html)
            self.assertIn("Auto-syncs every 60s", html)
            # Verify Apps and Configs are omitted
            self.assertNotIn("v2rayN", html)
            self.assertNotIn("Clash", html)
            self.assertNotIn("vmess://", html)
            self.assertNotIn("vless://", html)

    def test_06_json_sub_endpoint(self):
        """Verify GET /sub/<token>?format=json returns structured machine-readable payload."""
        token = self.user_active["sub_token"]
        url = f"http://127.0.0.1:{self.server_port}/sub/{token}?format=json"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["username"], "activeuser")
            self.assertEqual(data["status"], "ACTIVE")
            self.assertEqual(data["quota_bytes"], 10 * 1024 * 1024 * 1024)
            self.assertIn("GB", data["quota_formatted"])
            self.assertGreaterEqual(data["remaining_days"], 29)

    def test_07_status_variations(self):
        """Verify status labels for expired and quota exceeded users."""
        # Expired user JSON
        token_exp = self.mgr.get_user_by_username("expireduser")["sub_token"]
        url_exp = f"http://127.0.0.1:{self.server_port}/sub/{token_exp}?format=json"
        with urllib.request.urlopen(url_exp) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "EXPIRED")
            self.assertEqual(data["remaining_days"], 0)

        # Quota exceeded user JSON
        token_quota = self.mgr.get_user_by_username("quotauser")["sub_token"]
        url_quota = f"http://127.0.0.1:{self.server_port}/sub/{token_quota}?format=json"
        with urllib.request.urlopen(url_quota) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "QUOTA EXCEEDED")
            self.assertGreaterEqual(data["percentage"], 100.0)

    def test_08_404_for_invalid_tokens_and_paths(self):
        """Verify HTTP 404 for nonexistent tokens, invalid token formats, or rogue paths."""
        # Valid format but nonexistent token
        fake_token = "0" * 32
        url_fake = f"http://127.0.0.1:{self.server_port}/sub/{fake_token}"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(url_fake)
        self.assertEqual(ctx.exception.code, 404)

        # Invalid token format (e.g. wrong length)
        url_bad = f"http://127.0.0.1:{self.server_port}/sub/invalidtoken123"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(url_bad)
        self.assertEqual(ctx.exception.code, 404)

        # Arbitrary path
        url_rogue = f"http://127.0.0.1:{self.server_port}/admin"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(url_rogue)
        self.assertEqual(ctx.exception.code, 404)

    def test_09_in_memory_rate_limiter(self):
        """Verify ThreadSafeRateLimiter blocks requests exceeding threshold."""
        limiter = ThreadSafeRateLimiter(window_sec=60, max_requests=5)
        ip = "192.0.2.1"
        for _ in range(5):
            allowed, _ = limiter.is_allowed(ip)
            self.assertTrue(allowed)
        # 6th request should be blocked
        allowed, retry_after = limiter.is_allowed(ip)
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0)

        # Another IP should not be blocked
        allowed_other, _ = limiter.is_allowed("192.0.2.2")
        self.assertTrue(allowed_other)

    def test_10_cf_tunnel_helpers(self):
        """Verify Cloudflare tunnel configuration management and URL generation."""
        env_file = os.path.join(self.test_dir, "cf_tunnel.env")
        with patch("core.cf_tunnel.CF_ENV_PATH", env_file):
            # Initially empty
            cfg = cf_tunnel.load_cf_config()
            self.assertEqual(cfg["TUNNEL_TOKEN"], "")
            self.assertEqual(cfg["SUB_DOMAIN"], "")

            # Set custom subdomain
            cf_tunnel.set_custom_sub_domain("usage.nexiv.site")
            self.assertEqual(cf_tunnel.get_custom_sub_domain(), "usage.nexiv.site")

            # Check sub url generation
            url = cf_tunnel.get_sub_url("1234567890abcdef1234567890abcdef")
            self.assertEqual(url, "https://usage.nexiv.site/sub/1234567890abcdef1234567890abcdef")

            # Invalid domain validation
            with self.assertRaises(ValueError):
                cf_tunnel.set_custom_sub_domain("invalid domain with spaces!")

            # Portal port update
            cf_tunnel.set_portal_port(9090)
            self.assertEqual(cf_tunnel.get_portal_port(), 9090)
            with self.assertRaises(ValueError):
                cf_tunnel.set_portal_port(80) # Below 1024

    def test_11_head_request(self):
        """Verify HEAD request returns 200 OK without body."""
        url = f"http://127.0.0.1:{self.server_port}/health"
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), b"")

if __name__ == "__main__":
    unittest.main()
