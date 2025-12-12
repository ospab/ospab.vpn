#!/usr/bin/env python3
"""VLESS-Reality VPN Server"""

import asyncio
import hashlib
import logging
import os
import socket
import sys
import time
import uuid
from urllib.parse import urlparse

# --- Configuration ---
LISTEN_PORT = int(os.environ.get('PORT', 4433))
VLESS_UUID = os.environ.get('UUID', '')
REALITY_SNI = os.environ.get('SNI', 'www.microsoft.com')
MAGIC_HEADER = b'\x56\x4c\x45\x53'

# Security
MAX_FAILED_ATTEMPTS = 5
BAN_TIME = 3600
TIMEOUT = 300

# State
failed_attempts = {}
banned_ips = set()
connections = []

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('vless')


class Cipher:
    def __init__(self, key: str, nonce: bytes):
        self.key = key.encode() if isinstance(key, str) else key
        self.nonce = nonce
        self.counter = 0
        self.buf = b''

    def _gen(self):
        self.buf += hashlib.sha256(self.key + self.nonce + self.counter.to_bytes(8, 'big')).digest()
        self.counter += 1

    def process(self, data: bytes) -> bytes:
        out = bytearray()
        for b in data:
            if not self.buf:
                self._gen()
            out.append(b ^ self.buf[0])
            self.buf = self.buf[1:]
        return bytes(out)


def check_ban(ip: str) -> bool:
    if ip in banned_ips:
        if ip in failed_attempts:
            _, until = failed_attempts[ip]
            if time.time() < until:
                return False
            banned_ips.discard(ip)
            del failed_attempts[ip]
    return True


def record_fail(ip: str):
    if ip not in failed_attempts:
        failed_attempts[ip] = [1, 0]
    else:
        failed_attempts[ip][0] += 1
    if failed_attempts[ip][0] >= MAX_FAILED_ATTEMPTS:
        failed_attempts[ip][1] = time.time() + BAN_TIME
        banned_ips.add(ip)
        log.warning(f'Banned {ip}')


async def handle(reader, writer):
    addr = writer.get_extra_info('peername')
    ip = addr[0] if addr else ''
    
    if not check_ban(ip):
        writer.close()
        return

    try:
        # Handshake
        nonce = await asyncio.wait_for(reader.read(16), timeout=10)
        if len(nonce) < 16:
            writer.close()
            return

        cipher = Cipher(VLESS_UUID, nonce)
        handshake = cipher.process(await reader.read(4096))

        if MAGIC_HEADER not in handshake:
            record_fail(ip)
            writer.write(b'HTTP/1.1 404 Not Found\r\nServer: nginx\r\nConnection: close\r\n\r\n')
            await writer.drain()
            writer.close()
            return

        log.info(f'Client connected: {addr}')
        conn = {'writer': writer, 'cipher': cipher, 'addr': addr}
        connections.append(conn)

        try:
            while True:
                data = await asyncio.wait_for(reader.read(8192), timeout=TIMEOUT)
                if not data:
                    break

                plain = cipher.process(data)
                
                # Keep-alive
                if plain == b'PING':
                    writer.write(cipher.process(b'PONG'))
                    await writer.drain()
                    continue
                if plain == b'PONG':
                    continue

                text = plain.decode('utf-8', errors='ignore')
                
                # Proxy request
                if text.startswith(('GET ', 'POST ', 'CONNECT ', 'HEAD ', 'PUT ', 'DELETE ')):
                    await handle_proxy(reader, writer, cipher, text)
                    break
                    
        finally:
            if conn in connections:
                connections.remove(conn)

    except asyncio.TimeoutError:
        pass
    except Exception as e:
        log.debug(f'Error: {e}')
    finally:
        if not writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass


async def handle_proxy(client_reader, client_writer, cipher, request: str):
    """Handle HTTP/HTTPS proxy request"""
    lines = request.split('\n')
    req = lines[0].strip().split(' ')
    if len(req) < 2:
        return
    
    method, url = req[0], req[1]
    host, port = None, 80

    try:
        if method == 'CONNECT':
            if ':' in url:
                host, port = url.split(':')
                port = int(port)
            else:
                host = url
                port = 443
        else:
            if '://' in url:
                p = urlparse(url)
                host = p.hostname
                port = p.port or 80
            else:
                for line in lines:
                    if line.lower().startswith('host:'):
                        h = line.split(':', 1)[1].strip()
                        if ':' in h:
                            host, port = h.rsplit(':', 1)
                            port = int(port)
                        else:
                            host = h
                        break

        if not host:
            return

        log.info(f'Proxy: {method} {host}:{port}')
        
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )

        if method == 'CONNECT':
            client_writer.write(cipher.process(b'HTTP/1.1 200 Connection Established\r\n\r\n'))
            await client_writer.drain()
        else:
            remote_writer.write(request.encode())
            await remote_writer.drain()

        async def to_remote():
            try:
                while True:
                    data = await client_reader.read(4096)
                    if not data:
                        break
                    # Decrypt data from client before sending to target
                    decrypted = cipher.process(data)
                    remote_writer.write(decrypted)
                    await remote_writer.drain()
            except:
                pass
            finally:
                try:
                    remote_writer.close()
                except:
                    pass

        async def to_client():
            try:
                while True:
                    data = await remote_reader.read(4096)
                    if not data:
                        break
                    client_writer.write(cipher.process(data))
                    await client_writer.drain()
            except:
                pass

        await asyncio.gather(to_remote(), to_client())
        
    except Exception as e:
        err = f'HTTP/1.1 502 Bad Gateway\r\n\r\n{e}'
        client_writer.write(cipher.process(err.encode()))
        await client_writer.drain()


async def main():
    global VLESS_UUID, LISTEN_PORT, REALITY_SNI
    
    # CLI args: server.py [port] [uuid]
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        LISTEN_PORT = int(sys.argv[1])
    if len(sys.argv) > 2:
        VLESS_UUID = sys.argv[2]
    
    if not VLESS_UUID:
        VLESS_UUID = str(uuid.uuid4())

    # Get public IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
    except:
        ip = '0.0.0.0'

    print(f'''
╔══════════════════════════════════════════╗
║         VLESS-Reality Server             ║
╠══════════════════════════════════════════╣
║  IP:   {ip:<33}║
║  Port: {LISTEN_PORT:<33}║
║  UUID: {VLESS_UUID:<33}║
║  SNI:  {REALITY_SNI:<33}║
╚══════════════════════════════════════════╝
''')

    server = await asyncio.start_server(handle, '0.0.0.0', LISTEN_PORT)
    log.info(f'Listening on 0.0.0.0:{LISTEN_PORT}')
    
    await server.serve_forever()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\nStopped')
