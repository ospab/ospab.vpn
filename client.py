#!/usr/bin/env python3
"""ospab.vpn - Reality VPN Client"""
import asyncio
import hashlib
import hmac
import os
import socket
import struct
import sys

SERVER = os.environ.get('SERVER', '127.0.0.1')
PORT = int(os.environ.get('PORT', 443))
UUID = os.environ.get('UUID', '')
SNI = os.environ.get('SNI', 'www.microsoft.com')
PROXY_PORT = 10808


def derive_key(uuid_str):
    return hashlib.sha256(f"reality-auth-{uuid_str}".encode()).digest()


def build_client_hello(sni, uuid_str):
    """Build TLS 1.3 ClientHello with HMAC hidden in session_id"""
    nonce = os.urandom(16)
    auth_mac = hmac.new(derive_key(uuid_str), nonce, hashlib.sha256).digest()[:16]
    session_id = nonce + auth_mac
    
    sni_bytes = sni.encode()
    sni_ext = struct.pack('>HH', 0, len(sni_bytes) + 5)
    sni_ext += struct.pack('>H', len(sni_bytes) + 3) + b'\x00'
    sni_ext += struct.pack('>H', len(sni_bytes)) + sni_bytes
    
    versions_ext = struct.pack('>HH', 43, 3) + b'\x02\x03\x03'
    groups_ext = struct.pack('>HH', 10, 4) + b'\x00\x02\x00\x1d'
    sig_ext = struct.pack('>HH', 13, 4) + b'\x00\x02\x04\x03'
    key_share_ext = struct.pack('>HH', 51, 36) + struct.pack('>H', 34)
    key_share_ext += b'\x00\x1d\x00\x20' + os.urandom(32)
    
    extensions = sni_ext + versions_ext + groups_ext + sig_ext + key_share_ext
    cipher_suites = b'\x13\x01\x13\x02\x13\x03'
    
    hello = bytearray(b'\x03\x03') + os.urandom(32) + bytes([32]) + session_id
    hello += struct.pack('>H', len(cipher_suites)) + cipher_suites
    hello += b'\x01\x00' + struct.pack('>H', len(extensions)) + extensions
    
    handshake = bytes([0x01]) + len(hello).to_bytes(3, 'big') + hello
    record = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
    
    return bytes(record), nonce


class Cipher:
    """SHA256-CTR stream cipher"""
    def __init__(self, key, nonce):
        self.key = key.encode() if isinstance(key, str) else key
        self.nonce = nonce
        self.counter = 0
        self.buf = b''

    def _block(self):
        b = hashlib.sha256(self.key + self.nonce + self.counter.to_bytes(8, 'big')).digest()
        self.counter += 1
        return b

    def _xor(self, a, b):
        return (int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')).to_bytes(len(a), 'big')

    def process(self, data):
        if not data:
            return b''
        result, pos = [], 0
        if self.buf:
            use = min(len(self.buf), len(data))
            result.append(self._xor(data[:use], self.buf[:use]))
            self.buf, pos = self.buf[use:], use
        while pos < len(data):
            block = self._block()
            remaining = len(data) - pos
            if remaining >= 32:
                result.append(self._xor(data[pos:pos+32], block))
                pos += 32
            else:
                result.append(self._xor(data[pos:], block[:remaining]))
                self.buf = block[remaining:]
                break
        return b''.join(result)


class Multiplexer:
    """Client-side multiplexer"""
    def __init__(self):
        self.reader = None
        self.writer = None
        self.cipher = None
        self.streams = {}
        self.counter = 0
        self.lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self.connected = False

    async def connect(self, server, port, uuid_key, sni):
        async with self.lock:
            if self.connected:
                return True
            try:
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(server, port), 10)
                self.writer.get_extra_info('socket').setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                
                hello, nonce = build_client_hello(sni, uuid_key)
                self.writer.write(hello)
                await self.writer.drain()
                
                resp = await asyncio.wait_for(self.reader.read(1024), 10)
                if len(resp) < 10 or resp[0] != 0x16:
                    return False
                
                self.cipher = Cipher(uuid_key, nonce)
                self.connected = True
                asyncio.create_task(self._reader_loop())
                return True
            except Exception:
                return False

    async def _reader_loop(self):
        buf = b''
        try:
            while self.connected:
                chunk = await self.reader.read(65536)
                if not chunk:
                    break
                buf += self.cipher.process(chunk)
                
                while len(buf) >= 6:
                    sid, length = struct.unpack('>IH', buf[:6])
                    if len(buf) < 6 + length:
                        break
                    data, buf = buf[6:6+length], buf[6+length:]
                    
                    if sid in self.streams:
                        await self.streams[sid].put(None if length == 0 else data)
        except Exception:
            pass
        finally:
            self.connected = False
            for q in self.streams.values():
                await q.put(None)

    async def send(self, sid, data):
        async with self.write_lock:
            frame = struct.pack('>IH', sid, len(data)) + data
            self.writer.write(self.cipher.process(frame))
            await self.writer.drain()

    async def new_stream(self):
        async with self.lock:
            self.counter += 1
            self.streams[self.counter] = asyncio.Queue()
            return self.counter

    async def close_stream(self, sid):
        try:
            await self.send(sid, b'')
        except Exception:
            pass
        self.streams.pop(sid, None)

    def close(self):
        self.connected = False
        if self.writer:
            self.writer.close()
        self.streams.clear()


mux = Multiplexer()


async def proxy_handler(local_r, local_w):
    sid = None
    try:
        if not mux.connected:
            if not await mux.connect(SERVER, PORT, UUID, SNI):
                return local_w.close()

        sid = await mux.new_stream()

        async def to_remote():
            try:
                while data := await local_r.read(32768):
                    await mux.send(sid, data)
            except Exception:
                pass

        async def to_local():
            queue = mux.streams.get(sid)
            if not queue:
                return
            try:
                while True:
                    data = await queue.get()
                    if data is None:
                        break
                    local_w.write(data)
                    await local_w.drain()
            except Exception:
                pass

        await asyncio.gather(to_remote(), to_local())
    except Exception:
        pass
    finally:
        if sid:
            await mux.close_stream(sid)
        local_w.close()


def set_proxy(enable):
    if sys.platform == 'win32':
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                0, winreg.KEY_ALL_ACCESS)
            if enable:
                winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, f'127.0.0.1:{PROXY_PORT}')
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            else:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except Exception:
            pass


def setup():
    global SERVER, PORT, UUID, SNI
    if len(sys.argv) == 5:
        SERVER, PORT, UUID, SNI = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
        return True
    if len(sys.argv) > 1:
        print('Usage: client.py <server> <port> <uuid> <sni>')
        return False

    SERVER = input('[?] Server IP: ').strip()
    PORT = int(input('[?] Port [443]: ').strip() or 443)
    UUID = input('[?] UUID: ').strip()
    SNI = input('[?] SNI [www.microsoft.com]: ').strip() or 'www.microsoft.com'
    return bool(SERVER and UUID)


async def main():
    if not setup():
        return
    
    print(f'[*] Connecting to {SERVER}:{PORT}...')
    if not await mux.connect(SERVER, PORT, UUID, SNI):
        return print('[-] Connection failed')
    
    print(f'[+] Connected! Proxy: 127.0.0.1:{PROXY_PORT}')
    set_proxy(True)
    
    try:
        server = await asyncio.start_server(proxy_handler, '0.0.0.0', PROXY_PORT)
        await server.serve_forever()
    finally:
        set_proxy(False)
        mux.close()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[!] Stopped')
        set_proxy(False)
