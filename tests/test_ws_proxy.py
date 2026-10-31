#!/usr/bin/env python3
"""
Unit & Protocol Tests for VexTunnel SSH WebSocket Proxy
"""

import unittest
from core.ws_proxy import SSHWebSocketProxy

class TestWSProxy(unittest.TestCase):
    def setUp(self):
        self.proxy_101 = SSHWebSocketProxy("0.0.0.0", 80, "127.0.0.1", 109, response_code=101)
        self.proxy_200 = SSHWebSocketProxy("0.0.0.0", 80, "127.0.0.1", 109, response_code=200)

    def test_handshake_response_101(self):
        """Verify standard HTTP 101 Switching Protocols handshake response."""
        res = self.proxy_101.build_handshake_response()
        self.assertIn(b"HTTP/1.1 101 Switching Protocols\r\n", res)
        self.assertIn(b"Upgrade: websocket\r\n", res)
        self.assertIn(b"Connection: Upgrade\r\n", res)
        self.assertIn(b"Sec-WebSocket-Accept:", res)

    def test_handshake_response_200(self):
        """Verify HTTP 200 OK handshake response."""
        res = self.proxy_200.build_handshake_response()
        self.assertEqual(res, b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")

    def test_http_prefix_detection(self):
        """Verify HTTP prefix classification handles standard and custom mobile smuggling verbs."""
        HTTP_PREFIXES = (
            b"GET", b"POST", b"HEAD", b"CONNECT",
            b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"HTTP"
        )

        valid_http_samples = [
            b"GET / HTTP/1.1\r\nHost: hell.nexiv.site\r\n\r\n",
            b"GET- / HTTP/1.1\r\nHost: hell.nexiv.site\r\n\r\n",  # Custom dash payload
            b"POST /ws HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
        ]

        for sample in valid_http_samples:
            stripped = sample.lstrip()
            is_http = any(stripped.startswith(p) for p in HTTP_PREFIXES)
            self.assertTrue(is_http, f"Failed to recognize HTTP sample: {sample[:20]}")

        # Non-HTTP data (e.g. raw SSH identification banner)
        raw_ssh_banner = b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"
        is_http_ssh = any(raw_ssh_banner.lstrip().startswith(p) for p in HTTP_PREFIXES)
        self.assertFalse(is_http_ssh)

    def test_pipelined_ssh_data_extraction(self):
        """Verify pipelined SSH banner sent in the same initial packet as HTTP headers is cleanly extracted."""
        # Case 1: Pipelined packet with \r\n\r\n delimiter
        http_headers = b"GET / HTTP/1.1\r\nHost: hell.nexiv.site\r\nUpgrade: websocket\r\n\r\n"
        ssh_banner = b"SSH-2.0-NetMod-1.0.0\r\n"
        full_packet = http_headers + ssh_banner

        last_crlf = full_packet.rfind(b"\r\n\r\n")
        self.assertNotEqual(last_crlf, -1)
        extracted_ssh = full_packet[last_crlf + 4:]
        self.assertEqual(extracted_ssh, ssh_banner)

        # Case 2: Packet with only HTTP headers (no pipelined SSH data)
        only_http = b"GET / HTTP/1.1\r\nHost: hell.nexiv.site\r\n\r\n"
        last_crlf2 = only_http.rfind(b"\r\n\r\n")
        extracted_ssh2 = only_http[last_crlf2 + 4:]
        self.assertEqual(extracted_ssh2, b"")

    def test_ssl_proxy_parameters(self):
        """Verify SSL certificate arguments are stored correctly."""
        ssl_proxy = SSHWebSocketProxy(
            "0.0.0.0", 443, "127.0.0.1", 109,
            response_code=101,
            ssl_cert="/etc/vextunnel/certs/cert.pem",
            ssl_key="/etc/vextunnel/certs/key.pem"
        )
        self.assertEqual(ssl_proxy.listen_port, 443)
        self.assertEqual(ssl_proxy.ssl_cert, "/etc/vextunnel/certs/cert.pem")
        self.assertEqual(ssl_proxy.ssl_key, "/etc/vextunnel/certs/key.pem")

    def test_ssl_missing_files_error(self):
        """Verify calling start with non-existent SSL files raises FileNotFoundError."""
        import asyncio
        ssl_proxy = SSHWebSocketProxy(
            "0.0.0.0", 443, "127.0.0.1", 109,
            ssl_cert="/non_existent/cert.pem",
            ssl_key="/non_existent/key.pem"
        )
        with self.assertRaises(FileNotFoundError):
            asyncio.run(ssl_proxy.start())

if __name__ == "__main__":
    unittest.main()

