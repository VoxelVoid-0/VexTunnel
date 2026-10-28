#!/usr/bin/env python3
"""
VexTunnel - High-Performance Async SSH WebSocket Proxy
Author: VexElvn
License: MIT

Supports:
- HTTP / HTTPS (WSS) WebSocket connections
- Custom CDN / SNI Payloads (HTTP Custom, NapsternetV, HTTP Injector, NetMod, KPN Tunnel)
- Response status code customization (101 Switching Protocols, 200 OK)
- Asynchronous non-blocking I/O via Python asyncio
- Zero third-party dependencies (Uses Python standard library only)
"""

import asyncio
import logging
import argparse
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("WSProxy")

BUFFER_SIZE = 65536  # 64 KB buffer for high-throughput tunneling

class SSHWebSocketProxy:
    def __init__(self, listen_host: str, listen_port: int, target_host: str, target_port: int, response_code: int = 101):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.response_code = response_code
        self.active_connections = 0

    def build_handshake_response(self) -> bytes:
        """Generate appropriate HTTP response to complete the WebSocket handshake."""
        if self.response_code == 200:
            return b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        # Standard HTTP 101 Switching Protocols
        return (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        )

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        client_addr = client_writer.get_extra_info('peername')
        self.active_connections += 1
        logger.info(f"New client connected from {client_addr} (Active: {self.active_connections})")

        target_writer = None
        try:
            # Read the initial HTTP handshake payload
            initial_data = await asyncio.wait_for(client_reader.read(4096), timeout=15.0)
            if not initial_data:
                logger.warning(f"Empty handshake from {client_addr}")
                return

            HTTP_PREFIXES = (
                b"GET ", b"POST ", b"HEAD ", b"CONNECT ",
                b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"HTTP/"
            )

            stripped = initial_data.lstrip()
            is_http = any(stripped.startswith(prefix) for prefix in HTTP_PREFIXES)
            logger.info(f"Handshake from {client_addr} ({len(initial_data)} bytes, is_http={is_http}): {repr(initial_data[:80])}")

            # Connect to backend SSH daemon (e.g. Dropbear on 127.0.0.1:109)
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )

            if is_http:
                # Send HTTP 101 Handshake response to client
                response = self.build_handshake_response()
                client_writer.write(response)
                await client_writer.drain()
                logger.info(f"Sent 101 Switching Protocols to {client_addr}")

                # Extract any pipelined SSH data (e.g. SSH-2.0 identification string) after HTTP headers
                last_crlf = initial_data.rfind(b"\r\n\r\n")
                if last_crlf != -1:
                    ssh_initial_bytes = initial_data[last_crlf + 4:]
                else:
                    last_lf = initial_data.rfind(b"\n\n")
                    ssh_initial_bytes = initial_data[last_lf + 2:] if last_lf != -1 else b""

                if ssh_initial_bytes:
                    logger.info(f"Forwarding pipelined SSH bytes to Dropbear ({len(ssh_initial_bytes)} bytes): {repr(ssh_initial_bytes[:50])}")
                    target_writer.write(ssh_initial_bytes)
                    await target_writer.drain()
                    ssh_started = True
                else:
                    ssh_started = False
            else:
                # If non-WS raw connection, pass initial bytes straight to SSH
                target_writer.write(initial_data)
                await target_writer.drain()
                ssh_started = True

            # Client -> SSH pipe (filters out split HTTP request noise before SSH starts)
            async def client_to_ssh():
                nonlocal ssh_started
                try:
                    while True:
                        data = await client_reader.read(BUFFER_SIZE)
                        if not data:
                            logger.info(f"Client {client_addr} disconnected (EOF)")
                            break

                        if not ssh_started:
                            s_data = data.lstrip()
                            if any(s_data.startswith(p) for p in HTTP_PREFIXES):
                                logger.info(f"Absorbing extra HTTP chunk from {client_addr} ({len(data)} bytes): {repr(data[:60])}")
                                continue
                            else:
                                ssh_started = True
                                logger.info(f"SSH stream started from {client_addr} ({len(data)} bytes): {repr(data[:40])}")

                        target_writer.write(data)
                        await target_writer.drain()
                except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError) as e:
                    logger.debug(f"Client->SSH pipe error: {e}")
                finally:
                    try:
                        target_writer.close()
                        await target_writer.wait_closed()
                    except Exception:
                        pass

            # SSH -> Client pipe
            async def ssh_to_client():
                try:
                    while True:
                        data = await target_reader.read(BUFFER_SIZE)
                        if not data:
                            logger.info(f"SSH backend closed stream for {client_addr}")
                            break
                        client_writer.write(data)
                        await client_writer.drain()
                except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError) as e:
                    logger.debug(f"SSH->Client pipe error: {e}")
                finally:
                    try:
                        client_writer.close()
                        await client_writer.wait_closed()
                    except Exception:
                        pass

            pipe_to_ssh = asyncio.create_task(client_to_ssh())
            pipe_to_client = asyncio.create_task(ssh_to_client())

            await asyncio.wait([pipe_to_ssh, pipe_to_client], return_when=asyncio.FIRST_COMPLETED)

        except asyncio.TimeoutError:
            logger.warning(f"Handshake timeout from {client_addr}")
        except Exception as e:
            logger.debug(f"Connection error with {client_addr}: {e}")
        finally:
            self.active_connections -= 1
            logger.info(f"Closed connection from {client_addr} (Active: {self.active_connections})")
            
            # Clean up writers
            for writer in (client_writer, target_writer):
                if writer:
                    try:
                        writer.close()
                    except Exception:
                        pass

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.listen_host, self.listen_port
        )
        logger.info(f"SSH-WebSocket Proxy listening on {self.listen_host}:{self.listen_port}")
        logger.info(f"Forwarding to SSH backend at {self.target_host}:{self.target_port}")
        async with server:
            await server.serve_forever()

def main():
    parser = argparse.ArgumentParser(description="VexTunnel Async SSH WebSocket Proxy")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Host address to bind (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=80, help="Port to listen for WebSocket (default: 80)")
    parser.add_argument("--target-host", default="127.0.0.1", help="Backend SSH host (default: 127.0.0.1)")
    parser.add_argument("--target-port", type=int, default=109, help="Backend SSH port (default: 109 - Dropbear)")
    parser.add_argument("--response-code", type=int, default=101, choices=[101, 200], help="Handshake HTTP response code (101 or 200)")

    args = parser.parse_args()

    proxy = SSHWebSocketProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        target_host=args.target_host,
        target_port=args.target_port,
        response_code=args.response_code
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
