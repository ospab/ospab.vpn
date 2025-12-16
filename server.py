#!/usr/bin/env python3
"""ospab.vpn - Reality VPN Server"""
import asyncio
import hashlib
import hmac
import os
import socket
import struct
import sys
import uuid

PORT = int(os.environ.get('PORT', 443))
UUID = os.environ.get('UUID', '')
SNI = os.environ.get('SNI', 'www.microsoft.com')
DEBUG = False

def log(msg):
    if DEBUG:
        print(f'[LOG] {msg}')


def save_config(path='config.yml'):
    """Save config to YAML file"""
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"port: {PORT}\n")
            f.write(f"uuid: {UUID}\n")
            f.write(f"sni: {SNI}\n")
            f.write(f"debug: {str(DEBUG).lower()}\n")
        log(f'Конфиг сохранён в {path}')
    except Exception as e:
        log(f'Ошибка сохранения config.yml: {e}')


def derive_key(uuid_str):
    return hashlib.sha256(f"reality-auth-{uuid_str}".encode()).digest()


def verify_client_hello(data, uuid_str):
    """Verify TLS ClientHello contains our HMAC in session_id"""
    if len(data) < 76 or data[0] != 0x01:
        return False
    if data[38] != 32:
        return False
    
    session_id = data[39:71]
    nonce, provided_mac = session_id[:16], session_id[16:32]
    expected_mac = hmac.new(derive_key(uuid_str), nonce, hashlib.sha256).digest()[:16]
    return hmac.compare_digest(provided_mac, expected_mac)


def extract_sni(data):
    try:
        if len(data) < 76 or data[0] != 0x01:
            return None
        # Skip to extensions
        pos = 38  # after random
        session_id_len = data[pos]
        pos += 1 + session_id_len  # skip session_id
        cipher_len = struct.unpack('>H', data[pos:pos+2])[0]
        pos += 2 + cipher_len  # skip ciphers
        comp_len = data[pos]
        pos += 1 + comp_len  # skip compression
        ext_len = struct.unpack('>H', data[pos:pos+2])[0]
        pos += 2
        ext_end = pos + ext_len
        while pos + 4 < ext_end:
            ext_type = struct.unpack('>H', data[pos:pos+2])[0]
            ext_length = struct.unpack('>H', data[pos+2:pos+4])[0]
            if ext_type == 0:  # SNI
                # SNI extension data: list_len (2), entry_type (1)=0, name_len (2), name
                sni_pos = pos + 4 + 2 + 1
                if sni_pos + 2 < ext_end:
                    name_len = struct.unpack('>H', data[sni_pos:sni_pos+2])[0]
                    if sni_pos + 2 + name_len <= ext_end:
                        sni = data[sni_pos+2:sni_pos+2+name_len]
                        return sni.decode('utf-8')
            pos += 4 + ext_length
        return None
    except Exception:
        return None


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


class Stream:
    def __init__(self, writer):
        self.writer = writer


class Multiplexer:
    """Frame-based multiplexer: [4B stream_id][2B length][data]"""
    def __init__(self, reader, writer, cipher):
        self.reader = reader
        self.writer = writer
        self.cipher = cipher
        self.streams = {}
        self.lock = asyncio.Lock()

    async def send(self, stream_id, data):
        async with self.lock:
            frame = struct.pack('>IH', stream_id, len(data)) + data
            self.writer.write(self.cipher.process(frame))
            await self.writer.drain()

    async def close_stream(self, sid):
        try:
            await self.send(sid, b'')
        except Exception:
            pass
        if sid in self.streams:
            try:
                self.streams.pop(sid).writer.close()
            except Exception:
                pass

    async def handle_request(self, sid, data):
        text = data.decode('utf-8', errors='ignore')
        lines = text.split('\n')
        parts = lines[0].strip().split(' ')
        if len(parts) < 2:
            return await self.close_stream(sid)

        method, url = parts[0], parts[1]
        host, port = None, 80

        if method == 'CONNECT':
            host, port = (url.split(':') + ['443'])[:2]
            port = int(port)
        elif '://' in url:
            from urllib.parse import urlparse
            p = urlparse(url)
            host, port = p.hostname, p.port or 80
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
            return await self.close_stream(sid)

        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
            w.get_extra_info('socket').setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.streams[sid] = Stream(w)

            if method == 'CONNECT':
                await self.send(sid, b'HTTP/1.1 200 Connection Established\r\n\r\n')
            else:
                w.write(data)
                await w.drain()

            async def relay():
                try:
                    while chunk := await r.read(32768):
                        await self.send(sid, chunk)
                except Exception:
                    pass
                await self.close_stream(sid)

            asyncio.create_task(relay())
        except Exception:
            await self.close_stream(sid)

    async def run(self):
        buf = b''
        try:
            while True:
                chunk = await asyncio.wait_for(self.reader.read(65536), 300)
                if not chunk:
                    break
                buf += self.cipher.process(chunk)

                while len(buf) >= 6:
                    sid, length = struct.unpack('>IH', buf[:6])
                    if len(buf) < 6 + length:
                        break
                    data, buf = buf[6:6+length], buf[6+length:]

                    if length == 0:
                        if sid in self.streams:
                            self.streams.pop(sid).writer.close()
                    elif sid in self.streams:
                        self.streams[sid].writer.write(data)
                        await self.streams[sid].writer.drain()
                    else:
                        asyncio.create_task(self.handle_request(sid, data))
        except Exception:
            pass
        finally:
            for s in self.streams.values():
                try:
                    s.writer.close()
                except Exception:
                    pass


async def proxy_to_real(reader, writer, hello, sni):
    """Fallback: proxy to real SNI server"""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(sni or SNI, 443), 10)
        w.write(hello)
        await w.drain()

        async def pipe(src, dst):
            try:
                while data := await src.read(32768):
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            dst.close()

        await asyncio.gather(pipe(reader, w), pipe(r, writer))
    except Exception:
        writer.close()


def build_server_hello(session_id):
    body = b'\x03\x03' + os.urandom(32) + bytes([32]) + session_id + b'\x13\x01\x00\x00\x00'
    hs = bytes([0x02]) + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + len(hs).to_bytes(2, 'big') + hs


async def handle(reader, writer):
    addr = writer.get_extra_info('peername')
    log(f'Новое соединение от {addr}')
    sock = writer.get_extra_info('socket')
    if sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        data = await asyncio.wait_for(reader.read(4096), 10)
        if len(data) < 5 or data[0] != 0x16 or data[1:3] != b'\x03\x01':
            log(f'Не TLS 1.3 ClientHello от {addr}')
            return writer.close()
        hs_len = struct.unpack('>H', data[3:5])[0]
        if len(data) < 5 + hs_len:
            log(f'Неполный ClientHello от {addr}')
            return writer.close()
        hello = data[5:5+hs_len]
        if len(hello) < 76 or hello[0] != 0x01:
            log(f'Неверный handshake от {addr}')
            return writer.close()

        log(f'Получен ClientHello от {addr}: {len(hello)} байт')
        sni = extract_sni(hello)
        log(f'SNI от {addr}: {sni}')

        if verify_client_hello(hello, UUID):
            log(f'Reality аутентификация успешна для {addr}')
            nonce = hello[39:55]
            cipher = Cipher(UUID, nonce)
            writer.write(build_server_hello(nonce + hello[55:71]))
            await writer.drain()
            await Multiplexer(reader, writer, cipher).run()
        else:
            log(f'Reality аутентификация не пройдена для {addr}, проксирую на {sni}')
            await proxy_to_real(reader, writer, data, sni)
    except Exception as e:
        log(f'Ошибка в handle для {addr}: {e}')
    finally:
        if not writer.is_closing():
            writer.close()
        log(f'Соединение с {addr} закрыто')


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '0.0.0.0'


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
    ║           Reality VPN Server v2.0                 ║
    ╚═══════════════════════════════════════════════════╝
''')


def load_config(path='config.yml'):
    """Load config from YAML file"""
    global PORT, UUID, SNI, DEBUG
    try:
        log(f'Загрузка конфига из {path}...')
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
            DEBUG = config.get('debug', 'false').lower() == 'true'
            PORT = int(server.get('port', config.get('port', PORT)))
            UUID = server.get('uuid', config.get('uuid', UUID))
            SNI = server.get('sni', config.get('sni', SNI))
            log(f'Конфиг загружен: PORT={PORT}, UUID={UUID}, SNI={SNI}, DEBUG={DEBUG}')
            return True
    except FileNotFoundError:
        log('config.yml не найден')
        return False
    except Exception as e:
        log(f'Ошибка при загрузке config.yml: {e}')
        return False


def setup():
    global PORT, UUID, SNI
    
    # Try loading config.yml first
    if os.path.exists('config.yml') and load_config('config.yml'):
        if UUID and UUID != 'your-uuid-here':
            print('[+] Loaded config from config.yml')
            return True
    
    if len(sys.argv) == 4:
        PORT, UUID, SNI = int(sys.argv[1]), sys.argv[2], sys.argv[3]
        return True
    if len(sys.argv) > 1:
        print('Usage: server.py <port> <uuid> <sni>')
        return False

    show_banner()
    print('=' * 50)
    print('           Server Configuration')
    print('=' * 50)
    
    PORT = int(input('\n[?] Port [443]: ') or 443)
    UUID = input('[?] UUID (empty=generate): ') or str(uuid.uuid4())
    SNI = input('[?] SNI [www.microsoft.com]: ') or 'www.microsoft.com'
    save_config()
    return True


async def main():
    if not setup():
        return
    
    ip = get_local_ip()
    print(f'''
╔══════════════════════════════════════════════════════╗
║            ospab.vpn Reality Server                  ║
╠══════════════════════════════════════════════════════╣
║  Status:    RUNNING                                  ║
╠══════════════════════════════════════════════════════╣
║  IP:        {ip:<40} ║
║  Port:      {PORT:<40} ║
║  UUID:      {UUID:<40} ║
║  SNI:       {SNI:<40} ║
╚══════════════════════════════════════════════════════╝
''')
    await (await asyncio.start_server(handle, '0.0.0.0', PORT)).serve_forever()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[!] Stopped')
