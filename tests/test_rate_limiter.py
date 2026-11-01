#!/usr/bin/env python3
"""
VexTunnel - Phase 1: Anti-Abuse, Rate Limiter & Concurrency Guard Unit Tests
Covers:
1. IP string extraction from IPv4/IPv6 socket tuples
2. Per-IP concurrent connection ceiling enforcement
3. Per-IP arrival rate window throttling
4. Independent IP quota isolation
5. Memory cleanup and idle IP history eviction
6. Proxy admission rejection before handshake
7. Kernel anti-abuse firewall initialization safety
"""

import unittest
import asyncio
import time
from unittest.mock import MagicMock, AsyncMock, patch

from core.ws_proxy import IPRateLimiter, extract_ip, SSHWebSocketProxy
from core.quota_manager import setup_anti_abuse_firewall

class TestRateLimiter(unittest.TestCase):
    def test_01_extract_ip(self):
        """Verify peername parsing correctly extracts IPv4, IPv6, and handles edge cases."""
        self.assertEqual(extract_ip(('192.168.1.50', 44321)), '192.168.1.50')
        self.assertEqual(extract_ip(('2001:db8::1', 50000, 0, 0)), '2001:db8::1')
        self.assertEqual(extract_ip('10.0.0.1:1234'), '10.0.0.1:1234')
        self.assertEqual(extract_ip(None), 'unknown')
        self.assertEqual(extract_ip(()), 'unknown')

    def test_02_concurrency_ceiling(self):
        """Verify per-IP concurrent connection limit strictly rejects connections exceeding ceiling."""
        limiter = IPRateLimiter(max_conns_per_ip=3, max_rate=100, rate_window_sec=5.0)
        client_ip = "192.168.1.10"

        # Acquire 3 connections (up to ceiling)
        for i in range(3):
            allowed, reason = limiter.acquire(client_ip)
            self.assertTrue(allowed, f"Connection {i+1} should be admitted")
            self.assertEqual(reason, "")

        self.assertEqual(limiter.active_conns[client_ip], 3)

        # 4th connection must be rejected
        allowed, reason = limiter.acquire(client_ip)
        self.assertFalse(allowed, "4th connection must be rejected")
        self.assertIn("Max concurrent connections reached", reason)

        # Release one connection
        limiter.release(client_ip)
        self.assertEqual(limiter.active_conns[client_ip], 2)

        # Now acquire should succeed again
        allowed, reason = limiter.acquire(client_ip)
        self.assertTrue(allowed, "Connection should be admitted after release")

    def test_03_arrival_rate_limit(self):
        """Verify arrival rate sliding window rejects bursts exceeding max_rate."""
        limiter = IPRateLimiter(max_conns_per_ip=100, max_rate=4, rate_window_sec=1.0)
        client_ip = "10.0.0.5"

        # Rapidly acquire 4 connections
        for _ in range(4):
            allowed, _ = limiter.acquire(client_ip)
            self.assertTrue(allowed)

        # 5th connection must exceed arrival rate
        allowed, reason = limiter.acquire(client_ip)
        self.assertFalse(allowed)
        self.assertIn("Connection rate limit exceeded", reason)

        # Wait for window to expire
        time.sleep(1.05)

        # Next connection should be permitted
        allowed, reason = limiter.acquire(client_ip)
        self.assertTrue(allowed, "Connection should be permitted after sliding window expires")

    def test_04_ip_isolation(self):
        """Verify throttling one rogue IP does not affect other innocent client IPs."""
        limiter = IPRateLimiter(max_conns_per_ip=2, max_rate=10, rate_window_sec=5.0)

        # Max out IP 1
        limiter.acquire("1.1.1.1")
        limiter.acquire("1.1.1.1")
        allowed_1, _ = limiter.acquire("1.1.1.1")
        self.assertFalse(allowed_1)

        # IP 2 should still be admitted freely
        allowed_2, _ = limiter.acquire("2.2.2.2")
        self.assertTrue(allowed_2)
        allowed_3, _ = limiter.acquire("2.2.2.2")
        self.assertTrue(allowed_3)

    def test_05_memory_cleanup(self):
        """Verify periodic cleanup evicts idle IP history and prevents memory leaks."""
        limiter = IPRateLimiter(max_conns_per_ip=10, max_rate=10, rate_window_sec=0.1)

        limiter.acquire("172.16.0.1")
        limiter.release("172.16.0.1")
        self.assertIn("172.16.0.1", limiter.history)

        # Wait past rate_window_sec and trigger cleanup
        time.sleep(0.15)
        limiter._cleanup(now=time.time())

        self.assertNotIn("172.16.0.1", limiter.history, "Stale idle IP must be evicted from memory")

    def test_06_proxy_rate_limit_rejection(self):
        """Verify proxy handle_client immediately closes writer when rate limiter rejects."""
        limiter = IPRateLimiter(max_conns_per_ip=1, max_rate=10)
        proxy = SSHWebSocketProxy(
            listen_host="127.0.0.1",
            listen_port=9999,
            target_host="127.0.0.1",
            target_port=22,
            rate_limiter=limiter
        )

        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ('192.168.10.50', 50000)

        async def run_test():
            # First client connection passes rate limiter
            # We mock semaphore and reader to avoid real networking
            with patch.object(proxy.semaphore, "locked", return_value=False):
                # Simulate active connection holding the slot
                limiter.acquire('192.168.10.50')

                # Second client connection from same IP
                await proxy.handle_client(mock_reader, mock_writer)

                # Verify writer was closed immediately without allocating backend socket
                mock_writer.close.assert_called_once()

        asyncio.run(run_test())

    def test_07_anti_abuse_firewall_safety(self):
        """Verify setup_anti_abuse_firewall safely returns False on non-root or dev environment."""
        res = setup_anti_abuse_firewall()
        if hasattr(unittest, 'mock') and not (hasattr(import_os := __import__('os'), 'geteuid') and import_os.geteuid() == 0):
            self.assertFalse(res)

if __name__ == "__main__":
    unittest.main()
