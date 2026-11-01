#!/usr/bin/env python3
"""
VexTunnel - High-Performance Async SSH WebSocket Proxy (Hardened v1.2)
Author: VoxelVoid-0
License: MIT

Features:
- Kernel socket tuning (TCP_NODELAY, SO_KEEPALIVE, 1MB socket buffers)
- Dynamic streaming handshake reader (anti-fragmentation, up to 16KB header buffer)
- Slowloris & slow-client watchdog protection (10.0s handshake timeout)
- Connection admission control & concurrency budget (Semaphore max_conns)
- Non-blocking async I/O via Python asyncio standard library
- Dual HTTP (WS) and HTTPS (WSS) TLS encryption support
"""

import asyncio
import logging
import argparse
import sys
import os
import ssl
import socket
import base64
import hashlib
from typing import Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("WSProxy")

BUFFER_SIZE = 65536  # 64 KB buffer for high-throughput tunneling
MAX_HEADER_SIZE = 16384  # 16 KB max HTTP handshake header size
HANDSHAKE_TIMEOUT = 10.0  # 10.0s Slowloris & slow-peer watchdog timeout

HTTP_PREFIXES = (
    b"GET", b"POST", b"HEAD", b"CONNECT",
    b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"HTTP"
)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def parse_http_headers(raw: bytes) -> Dict[str, str]:
    """Parse HTTP headers from raw byte buffer into lowercase key-value dictionary."""
    text = raw.decode("latin-1", errors="replace")
    headers = {}
    for line in text.split("\r\n"):
        if not line:
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
        elif "\n" in line:
            # Handle LF-only separated headers
            for subline in line.split("\n"):
                if ":" in subline:
                    k, v = subline.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
    return headers

def compute_websocket_accept(client_key: str) -> str:
    """Compute dynamic RFC 6455 Sec-WebSocket-Accept token from Sec-WebSocket-Key."""
    if not client_key:
        return "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    magic = client_key.strip() + WS_GUID
    try:
        digest = hashlib.sha1(magic.encode("utf-8"), usedforsecurity=False).digest()  # nosec B324 - RFC 6455 requires SHA1
    except TypeError:
        digest = hashlib.sha1(magic.encode("utf-8")).digest()  # nosec B324 - RFC 6455 requires SHA1
    return base64.b64encode(digest).decode("ascii")

def configure_socket(sock: socket.socket):
    """Tune OS-level socket options for ultra-low latency & high throughput."""
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        # Linux TCP Keepalive tuning
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

        # 1 MB Send/Receive buffers
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
    except Exception as e:
        logger.debug(f"Socket tuning warning: {e}")

class SSHWebSocketProxy:
    def __init__(self, listen_host: str, listen_port: int, target_host: str, target_port: int,
                 response_code: int = 101, ssl_cert: str = None, ssl_key: str = None, max_conns: int = 2048):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.response_code = response_code
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.max_conns = max_conns
        self.semaphore = asyncio.Semaphore(max_conns)
        self.active_connections = 0

    def build_handshake_response(self, client_key: Optional[str] = None) -> bytes:
        """Generate appropriate HTTP response to complete RFC 6455 WebSocket handshake."""
        if self.response_code == 200:
            return b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"

        accept_token = compute_websocket_accept(client_key) if client_key else "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        return (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            + f"Sec-WebSocket-Accept: {accept_token}\r\n\r\n".encode("ascii")
        )

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        client_addr = client_writer.get_extra_info('peername')
        
        # 1. Connection Admission Gate
        if self.semaphore.locked():
            logger.warning(f"Connection budget exhausted ({self.max_conns}). Rejecting client from {client_addr}")
            client_writer.close()
            return

        async with self.semaphore:
            self.active_connections += 1
            logger.info(f"Accepted connection from {client_addr} (Active: {self.active_connections}/{self.max_conns})")

            # Apply kernel socket tuning to client socket
            client_sock = client_writer.get_extra_info('socket')
            if client_sock:
                configure_socket(client_sock)

            target_writer = None
            try:
                # 2. Dynamic Streaming Handshake Reader (Anti-Fragmentation & Slowloris Watchdog)
                header_buffer = bytearray()

                async def read_header_stream():
                    nonlocal header_buffer
                    while True:
                        chunk = await client_reader.read(4096)
                        if not chunk:
                            break
                        header_buffer.extend(chunk)
                        if b"\r\n\r\n" in header_buffer or b"\n\n" in header_buffer:
                            break
                        if len(header_buffer) >= MAX_HEADER_SIZE:
                            break

                try:
                    await asyncio.wait_for(read_header_stream(), timeout=HANDSHAKE_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.warning(f"Slowloris watchdog: Handshake timeout ({HANDSHAKE_TIMEOUT}s) from {client_addr}. Closing socket.")
                    return

                initial_data = bytes(header_buffer)
                if not initial_data:
                    logger.warning(f"Empty handshake received from {client_addr}")
                    return

                # Detect HTTP handshake verbs
                stripped = initial_data.lstrip()
                is_http = any(stripped.startswith(prefix) for prefix in HTTP_PREFIXES)
                logger.info(f"Handshake from {client_addr} ({len(initial_data)} bytes, is_http={is_http}): {repr(initial_data[:80])}")

                # 3. Connect to backend SSH daemon (e.g. Dropbear 127.0.0.1:109)
                target_reader, target_writer = await asyncio.open_connection(
                    self.target_host, self.target_port
                )
                target_sock = target_writer.get_extra_info('socket')
                if target_sock:
                    configure_socket(target_sock)

                if is_http:
                    headers = parse_http_headers(initial_data)
                    client_key = headers.get("sec-websocket-key")

                    # Send HTTP 101/200 Handshake response to mobile client (RFC 6455 dynamic token)
                    response = self.build_handshake_response(client_key=client_key)
                    client_writer.write(response)
                    await client_writer.drain()
                    logger.info(f"Completed HTTP handshake with {client_addr} (RFC key dynamic accept: {bool(client_key)})")

                    # Extract any pipelined SSH banner bytes arriving in the initial packet
                    last_crlf = initial_data.rfind(b"\r\n\r\n")
                    if last_crlf != -1:
                        ssh_initial_bytes = initial_data[last_crlf + 4:]
                    else:
                        last_lf = initial_data.rfind(b"\n\n")
                        ssh_initial_bytes = initial_data[last_lf + 2:] if last_lf != -1 else b""

                    if ssh_initial_bytes:
                        logger.info(f"Forwarding {len(ssh_initial_bytes)} pipelined SSH bytes to Dropbear: {repr(ssh_initial_bytes[:50])}")
                        target_writer.write(ssh_initial_bytes)
                        await target_writer.drain()
                        ssh_started = True
                    else:
                        ssh_started = False
                else:
                    # Direct raw connection (non-WS fallback)
                    target_writer.write(initial_data)
                    await target_writer.drain()
                    ssh_started = True

                # 4. Bi-Directional Asynchronous Stream Pipes with Backpressure Control
                async def pipe_client_to_ssh():
                    nonlocal ssh_started
                    try:
                        while True:
                            data = await client_reader.read(BUFFER_SIZE)
                            if not data:
                                break

                            # Filter out any multi-chunk HTTP noise before raw SSH stream starts
                            if not ssh_started:
                                s_data = data.lstrip()
                                if any(s_data.startswith(p) for p in HTTP_PREFIXES):
                                    logger.info(f"Absorbing fragmented HTTP noise from {client_addr} ({len(data)} bytes)")
                                    continue
                                else:
                                    ssh_started = True

                            target_writer.write(data)
                            await target_writer.drain()
                    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                        pass
                    finally:
                        try:
                            target_writer.close()
                        except Exception:
                            pass

                async def pipe_ssh_to_client():
                    try:
                        while True:
                            data = await target_reader.read(BUFFER_SIZE)
                            if not data:
                                break
                            client_writer.write(data)
                            await client_writer.drain()
                    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                        pass
                    finally:
                        try:
                            client_writer.close()
                        except Exception:
                            pass

                task_c2s = asyncio.create_task(pipe_client_to_ssh())
                task_s2c = asyncio.create_task(pipe_ssh_to_client())

                await asyncio.wait([task_c2s, task_s2c], return_when=asyncio.FIRST_COMPLETED)

            except Exception as e:
                logger.debug(f"Connection exception from {client_addr}: {e}")
            finally:
                self.active_connections -= 1
                logger.info(f"Terminated session for {client_addr} (Active: {self.active_connections})")

                # Close both streams cleanly
                for writer in (client_writer, target_writer):
                    if writer:
                        try:
                            writer.close()
                        except Exception:
                            pass

    async def start(self):
        ssl_ctx = None
        if self.ssl_cert and self.ssl_key:
            if not os.path.exists(self.ssl_cert):
                raise FileNotFoundError(f"SSL certificate file not found: {self.ssl_cert}")
            if not os.path.exists(self.ssl_key):
                raise FileNotFoundError(f"SSL private key file not found: {self.ssl_key}")
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
            logger.info(f"SSL/TLS termination enabled on port {self.listen_port} using {self.ssl_cert}")

        server = await asyncio.start_server(
            self.handle_client, self.listen_host, self.listen_port, ssl=ssl_ctx
        )
        proto = "HTTPS (WSS)" if ssl_ctx else "HTTP (WS)"
        logger.info(f"{proto} Proxy listening on {self.listen_host}:{self.listen_port} [Max Conns: {self.max_conns}]")
        logger.info(f"Backend forwarding target: {self.target_host}:{self.target_port}")
        async with server:
            await server.serve_forever()

def main():
    parser = argparse.ArgumentParser(description="VexTunnel High-Performance Async SSH WebSocket Proxy")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Host address to bind (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=80, help="Port to listen for WebSocket (default: 80)")
    parser.add_argument("--target-host", default="127.0.0.1", help="Backend SSH host (default: 127.0.0.1)")
    parser.add_argument("--target-port", type=int, default=109, help="Backend SSH port (default: 109 - Dropbear)")
    parser.add_argument("--response-code", type=int, default=101, choices=[101, 200], help="Handshake HTTP response code (101 or 200)")
    parser.add_argument("--ssl-cert", default=None, help="Path to SSL certificate file")
    parser.add_argument("--ssl-key", default=None, help="Path to SSL private key file")
    parser.add_argument("--max-conns", type=int, default=2048, help="Maximum concurrent connections admission limit (default: 2048)")

    args = parser.parse_args()

    proxy = SSHWebSocketProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        target_host=args.target_host,
        target_port=args.target_port,
        response_code=args.response_code,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        max_conns=args.max_conns
    )

    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        logger.info("Proxy server stopped by user.")
    except Exception as e:
        logger.critical(f"Server fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
