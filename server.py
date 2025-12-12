#!/usr/bin/env python3
import asyncio
import hashlib
import logging
import os
import socket
import struct
import sys
import time
import uuid

LISTEN_PORT = int(os.environ.get('PORT', 4433))
VLESS_UUID = os.environ.get('UUID', '')
REALITY_SNI = os.environ.get('SNI', 'www.microsoft.com')
MAGIC_HEADER = b'\x56\x4c\x45\x53'

MAX_FAILED_ATTEMPTS = 5
BAN_TIME = 3600
TIMEOUT = 300

failed_attempts = {}
banned_ips = set()

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('vless')


class Cipher:
    def __init__(self, key, nonce):
        self.key = key.encode() if isinstance(key, str) else key
        self.nonce = nonce
        self.counter = 0
        self.buf = b''

    def _gen_block(self):
        block = hashlib.sha256(self.key + self.nonce + self.counter.to_bytes(8, 'big')).digest()
        self.counter += 1
        return block

    def _xor_bytes(self, a, b):
        return (int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')).to_bytes(len(a), 'big')

    def process(self, data):
        if not data:
            return b''
        
        result = []
        pos = 0
        data_len = len(data)
        
        if self.buf:
            use = min(len(self.buf), data_len)
            result.append(self._xor_bytes(data[:use], self.buf[:use]))
            self.buf = self.buf[use:]
            pos = use
        
        while pos < data_len:
            block = self._gen_block()
            remaining = data_len - pos
            if remaining >= 32:
                result.append(self._xor_bytes(data[pos:pos+32], block))
                pos += 32
            else:
                result.append(self._xor_bytes(data[pos:], block[:remaining]))
                self.buf = block[remaining:]
                pos = data_len
        
        return b''.join(result)


def check_ban(ip):
    if ip in banned_ips:
        if ip in failed_attempts:
            _, until = failed_attempts[ip]
            if time.time() < until:
                return False
            banned_ips.discard(ip)
            del failed_attempts[ip]
    return True


def record_fail(ip):
    if ip not in failed_attempts:
        failed_attempts[ip] = [1, 0]
    else:
        failed_attempts[ip][0] += 1
    if failed_attempts[ip][0] >= MAX_FAILED_ATTEMPTS:
        failed_attempts[ip][1] = time.time() + BAN_TIME
        banned_ips.add(ip)
        log.warning(f'Banned {ip}')


class StreamInfo:
    def __init__(self, remote_writer):
        self.remote_writer = remote_writer
        self.queue = asyncio.Queue()


class MultiplexServer:
    def __init__(self, reader, writer, cipher, addr):
        self.reader = reader
        self.writer = writer
        self.cipher = cipher
        self.addr = addr
        self.streams = {}
        self.lock = asyncio.Lock()

    async def send_frame(self, stream_id, data):
        async with self.lock:
            header = struct.pack('>IH', stream_id, len(data))
            self.writer.write(self.cipher.process(header + data))
            await self.writer.drain()

    async def close_stream(self, stream_id):
        try:
            await self.send_frame(stream_id, b'')
        except Exception:
            pass
        if stream_id in self.streams:
            info = self.streams.pop(stream_id)
            try:
                info.remote_writer.close()
            except Exception:
                pass

    async def handle_stream(self, stream_id, initial_data):
        text = initial_data.decode('utf-8', errors='ignore')
        lines = text.split('\n')
        req = lines[0].strip().split(' ')
        if len(req) < 2:
            await self.close_stream(stream_id)
            return

        method, url = req[0], req[1]
        host, port = None, 80

        try:
            if method == 'CONNECT':
                if ':' in url:
                    host, p = url.split(':')
                    port = int(p)
                else:
                    host, port = url, 443
            else:
                if '://' in url:
                    from urllib.parse import urlparse
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
                await self.close_stream(stream_id)
                return

            log.info(f'[{stream_id}] {method} {host}:{port}')
            
            remote_r, remote_w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            
            rsock = remote_w.get_extra_info('socket')
            if rsock:
                rsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            stream_info = StreamInfo(remote_w)
            self.streams[stream_id] = stream_info

            if method == 'CONNECT':
                await self.send_frame(stream_id, b'HTTP/1.1 200 Connection Established\r\n\r\n')
            else:
                remote_w.write(initial_data)
                await remote_w.drain()

            async def from_remote():
                try:
                    while True:
                        data = await remote_r.read(65536)
                        if not data:
                            break
                        await self.send_frame(stream_id, data)
                except Exception:
                    pass
                finally:
                    await self.close_stream(stream_id)

            asyncio.create_task(from_remote())

        except Exception as e:
            log.debug(f'Stream {stream_id} error: {e}')
            err = f'HTTP/1.1 502 Bad Gateway\r\n\r\n{e}'
            try:
                await self.send_frame(stream_id, err.encode())
            except Exception:
                pass
            await self.close_stream(stream_id)

    async def run(self):
        buf = b''
        try:
            while True:
                chunk = await asyncio.wait_for(self.reader.read(131072), timeout=TIMEOUT)
                if not chunk:
                    break
                
                buf += self.cipher.process(chunk)
                
                while len(buf) >= 6:
                    stream_id, length = struct.unpack('>IH', buf[:6])
                    if len(buf) < 6 + length:
                        break
                    
                    data = buf[6:6 + length]
                    buf = buf[6 + length:]
                    
                    if length == 0:
                        if stream_id in self.streams:
                            info = self.streams.pop(stream_id)
                            try:
                                info.remote_writer.close()
                            except Exception:
                                pass
                        continue
                    
                    if stream_id in self.streams:
                        try:
                            self.streams[stream_id].remote_writer.write(data)
                            await self.streams[stream_id].remote_writer.drain()
                        except Exception:
                            await self.close_stream(stream_id)
                    else:
                        asyncio.create_task(self.handle_stream(stream_id, data))
                        
        except asyncio.TimeoutError:
            log.info(f'Timeout: {self.addr}')
        except Exception as e:
            log.debug(f'Error: {e}')
        finally:
            for sid in list(self.streams.keys()):
                try:
                    self.streams[sid].remote_writer.close()
                except Exception:
                    pass
            self.streams.clear()


async def handle(reader, writer):
    addr = writer.get_extra_info('peername')
    ip = addr[0] if addr else ''
    
    if not check_ban(ip):
        writer.close()
        return

    sock = writer.get_extra_info('socket')
    if sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)

    try:
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

        log.info(f'Connected: {addr}')
        
        mux = MultiplexServer(reader, writer, cipher, addr)
        await mux.run()

    except asyncio.TimeoutError:
        pass
    except Exception as e:
        log.debug(f'Error: {e}')
    finally:
        if not writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        log.info(f'Disconnected: {addr}')


def get_config():
    global VLESS_UUID, LISTEN_PORT, REALITY_SNI
    
    if len(sys.argv) == 4:
        try:
            LISTEN_PORT = int(sys.argv[1])
            VLESS_UUID = sys.argv[2]
            REALITY_SNI = sys.argv[3]
            return True
        except ValueError:
            print('[-] Port must be a number')
            return False
    elif len(sys.argv) > 1:
        print('Usage: server.py <port> <uuid> <sni>')
        return False
    
    print('\n' + '=' * 50)
    print('       VLESS-Reality Server Configuration')
    print('=' * 50)
    
    try:
        port_in = input('\n[?] Port [4433]: ').strip()
        if port_in:
            LISTEN_PORT = int(port_in)
    except ValueError:
        print('[-] Invalid port')
        return False
    
    uuid_in = input('[?] UUID (empty = generate): ').strip()
    if uuid_in:
        VLESS_UUID = uuid_in
    else:
        VLESS_UUID = str(uuid.uuid4())
        print(f'[+] Generated UUID: {VLESS_UUID}')
    
    sni_in = input('[?] SNI [www.microsoft.com]: ').strip()
    if sni_in:
        REALITY_SNI = sni_in
    
    return True


async def main():
    if not get_config():
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = '0.0.0.0'

    print(f'''
╔══════════════════════════════════════════════════╗
║           VLESS-Reality VPN Server               ║
╠══════════════════════════════════════════════════╣
║  Status:  RUNNING                                ║
╠══════════════════════════════════════════════════╣
║  IP:      {ip:<38} ║
║  Port:    {LISTEN_PORT:<38} ║
║  UUID:    {VLESS_UUID:<38} ║
║  SNI:     {REALITY_SNI:<38} ║
╠══════════════════════════════════════════════════╣
║  Share this with client:                         ║
║  {ip}:{LISTEN_PORT} | {VLESS_UUID[:20]}...       ║
╚══════════════════════════════════════════════════╝
''')

    server = await asyncio.start_server(handle, '0.0.0.0', LISTEN_PORT)
    log.info(f'Listening on 0.0.0.0:{LISTEN_PORT}')
    
    await server.serve_forever()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[!] Server stopped')
