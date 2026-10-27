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

            request_str = initial_data.decode('latin1', errors='ignore')
            # Check for WebSocket Upgrade or standard HTTP GET/CONNECT request
            is_ws = (
                "upgrade" in request_str.lower() or 
                "websocket" in request_str.lower() or
                "http/" in request_str.lower()
            )

            # Connect to backend SSH daemon (e.g. Dropbear on 127.0.0.1:109)
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )

            if is_ws:
                # Send HTTP 101 Handshake response to client
                response = self.build_handshake_response()
                client_writer.write(response)
                await client_writer.drain()
            else:
                # If non-WS raw connection, pass initial bytes straight to SSH
                target_writer.write(initial_data)
                await target_writer.drain()

            # Pipe bi-directionally between client and SSH server
            async def forward(src_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter):
                try:
                    while True:
                        data = await src_reader.read(BUFFER_SIZE)
                        if not data:
                            break
                        dst_writer.write(data)
                        await dst_writer.drain()
                except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    try:
                        dst_writer.close()
                        await dst_writer.wait_closed()
                    except Exception:
                        pass

            pipe_to_ssh = asyncio.create_task(forward(client_reader, target_writer))
            pipe_to_client = asyncio.create_task(forward(target_reader, client_writer))

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
