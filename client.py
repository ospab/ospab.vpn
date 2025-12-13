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
                print(f'[LOG] Подключение к {server}:{port}...')
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(server, port), 10)
                self.writer.get_extra_info('socket').setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                
                hello, nonce = build_client_hello(sni, uuid_key)
                print(f'[LOG] Отправка ClientHello: {len(hello)} байт')
                self.writer.write(hello)
                await self.writer.drain()
                
                resp = await asyncio.wait_for(self.reader.read(1024), 10)
                print(f'[LOG] Получен ответ: {len(resp)} байт, начинается с {resp[:10].hex() if resp else "пусто"}')
                if len(resp) >= 6 and resp[0] == 0x16:
                    try:
                        hs_len = struct.unpack('>H', resp[3:5])[0]
                        if len(resp) >= 5 + hs_len and resp[5] == 0x02:
                            print(f'[LOG] Успешное подключение к Reality серверу {server}:{port}')
                            return True
                    except Exception:
                        pass
                print('[LOG] Ответ не является корректным Server Hello')
                return False
            except Exception as e:
                print(f'[LOG] Ошибка подключения: {e}')
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


def show_banner():
    print('''
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║   ▒█████    ██████  ██▓███   ▄▄▄       ▄▄▄▄       ║
    ║  ▒██▒  ██▒▒██    ▒ ▓██░  ██▒▒████▄    ▓█████▄     ║
    ║  ▒██░  ██▒░ ▓██▄   ▓██░ ██▓▒▒██  ▀█▄  ▒██▒ ▄██    ║
    ║  ▒██   ██░  ▒   ██▒▒██▄█▓▒ ▒░██▄▄▄▄██ ▒██░█▀      ║
    ║  ░ ████▓▒░▒██████▒▒▒██▒ ░  ░ ▓█   ▓██▒░▓█  ▀█▓    ║
    ║  ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░ ▒▒   ▓▒█░░▒▓███▀▒    ║
    ║    ░ ▒ ▒░ ░ ░▒  ░ ░░▒ ░       ▒   ▒▒ ░▒░▒   ░     ║
    ║  ░ ░ ░ ▒  ░  ░  ░  ░░         ░   ▒    ░    ░     ║
    ║      ░ ░        ░                 ░  ░ ░          ║
    ║                                             ░     ║
    ║           Reality VPN Client v2.0                 ║
    ╚═══════════════════════════════════════════════════╝
''')


def load_config(path='config.yml'):
    """Load config from YAML file"""
    global SERVER, PORT, UUID, SNI, PROXY_PORT
    try:
        print(f'[LOG] Загрузка конфига из {path}...')
        with open(path, 'r', encoding='utf-8') as f:
            current_section = None
            config = {}
            for line in f:
                line = line.rstrip()
                if not line or line.strip().startswith('#'):
                    continue
                if not line.startswith(' ') and line.endswith(':'):
                    current_section = line[:-1].strip()
                    config[current_section] = {}
                elif ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if current_section:
                        config[current_section][key] = value
                    else:
                        config[key] = value
            server = config.get('server', {})
            proxy = config.get('proxy', {})
            print(f'[LOG] server: {server}')
            print(f'[LOG] proxy: {proxy}')
            SERVER = server.get('ip', SERVER)
            PORT = int(server.get('port', PORT))
            UUID = server.get('uuid', UUID)
            SNI = server.get('sni', SNI)
            PROXY_PORT = int(proxy.get('port', PROXY_PORT))
            print(f'[LOG] Конфиг загружен: SERVER={SERVER}, PORT={PORT}, UUID={UUID}, SNI={SNI}, PROXY_PORT={PROXY_PORT}')
            return True
    except FileNotFoundError:
        print(f'[LOG] config.yml не найден')
        return False
    except Exception as e:
        print(f'[LOG] Ошибка при загрузке config.yml: {e}')
        return False


def setup():
    global SERVER, PORT, UUID, SNI
    
    # Try loading config.yml first
    if os.path.exists('config.yml') and load_config('config.yml'):
        if SERVER and UUID and UUID != 'your-uuid-here':
            print('[LOG] Конфиг успешно загружен из config.yml')
            return True
    
    if len(sys.argv) == 5:
        SERVER, PORT, UUID, SNI = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
        return True
    if len(sys.argv) > 1:
        print('Usage: client.py <server> <port> <uuid> <sni>')
        return False

    show_banner()
    print('=' * 50)
    print('           Connection Setup')
    print('=' * 50)
    
    while True:
        SERVER = input('\n[?] Server IP: ').strip()
        if SERVER:
            break
        print('    [-] Server IP is required')
    
    PORT = int(input('[?] Port [443]: ').strip() or 443)
    
    while True:
        UUID = input('[?] UUID: ').strip()
        if UUID:
            break
        print('    [-] UUID is required')
    
    SNI = input('[?] SNI [www.microsoft.com]: ').strip() or 'www.microsoft.com'
    return True


async def test_connection():
    print(f'\n[LOG] Проверка соединения Reality: {SERVER}:{PORT}, UUID={UUID}, SNI={SNI}')
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(SERVER, PORT), 5)
        hello, nonce = build_client_hello(SNI, UUID)
        print(f'[LOG] Отправка ClientHello: {len(hello)} байт')
        w.write(hello)
        await w.drain()
        resp = await asyncio.wait_for(r.read(1024), 5)
        w.close()
        print(f'[LOG] Получен ответ: {len(resp)} байт, начинается с {resp[:10].hex() if resp else "пусто"}')
        if len(resp) >= 6 and resp[0] == 0x16:
            try:
                hs_len = struct.unpack('>H', resp[3:5])[0]
                if len(resp) >= 5 + hs_len and resp[5] == 0x02:
                    print('[LOG] Reality handshake успешен!')
                    return True
            except Exception:
                pass
        print('[LOG] Некорректный ответ сервера')
        return False
    except Exception as e:
        print(f'[LOG] Ошибка соединения: {e}')
        return False


async def main():
    print('[LOG] Запуск клиента...')
    if not setup():
        print('[LOG] setup() вернул False, выход')
        return
    print('[LOG] setup() завершён')
    if not await test_connection():
        print('[LOG] test_connection() неудачен, выход')
        return
    print('[LOG] test_connection() успешен')
    if not await mux.connect(SERVER, PORT, UUID, SNI):
        print('[LOG] mux.connect() неудачен, выход')
        return print('[-] Failed to establish tunnel')
    print('[LOG] mux.connect() успешен')
    print(f'''
╔══════════════════════════════════════════════════════╗
║            ospab.vpn Reality Client                  ║
╠══════════════════════════════════════════════════════╣
║  Server:    {SERVER}:{PORT:<28} ║
║  Local:     127.0.0.1:{PROXY_PORT:<30} ║
║  SNI:       {SNI:<40} ║
║  Status:    CONNECTED                                ║
╠══════════════════════════════════════════════════════╣
║  Features:                                           ║
║  • Real TLS handshake                                ║
║  • Hidden authentication                             ║
║  • DPI-resistant                                     ║
╚══════════════════════════════════════════════════════╝
''')
    set_proxy(True)
    print(f'[LOG] HTTP Proxy слушает на 0.0.0.0:{PROXY_PORT}')
    print('[*] Press Ctrl+C to disconnect\n')
    try:
        print('[LOG] Запуск asyncio.start_server...')
        server = await asyncio.start_server(proxy_handler, '0.0.0.0', PROXY_PORT)
        print('[LOG] Сервер запущен, ожидание соединений...')
        await server.serve_forever()
    finally:
        set_proxy(False)
        mux.close()
        print('\n[LOG] Отключено')


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[!] Stopped')
        set_proxy(False)
