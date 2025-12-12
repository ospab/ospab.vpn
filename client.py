#!/usr/bin/env python3
import asyncio
import hashlib
import os
import random
import socket
import struct
import sys

SERVER_IP = os.environ.get('SERVER', '127.0.0.1')
SERVER_PORT = int(os.environ.get('PORT', 4433))
VLESS_UUID = os.environ.get('UUID', '')
REALITY_SNI = os.environ.get('SNI', 'www.microsoft.com')
MAGIC_HEADER = b'\x56\x4c\x45\x53'
PROXY_PORT = 10808


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


def make_handshake(sni):
    tls = b'\x16\x03\x01\x00\xfa'
    http = f'GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: keep-alive\r\n\r\n'.encode()
    pos = random.randint(10, len(http) - 5)
    return tls + http[:pos] + MAGIC_HEADER + http[pos:]


class MultiplexClient:
    def __init__(self):
        self.reader = None
        self.writer = None
        self.cipher = None
        self.streams = {}
        self.stream_counter = 0
        self.lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self.connected = False
        self.reader_task = None

    async def connect(self, server_ip, server_port, uuid_key, sni):
        async with self.lock:
            if self.connected:
                return True
            
            try:
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(server_ip, server_port), timeout=10
                )
                
                sock = self.writer.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
                
                nonce = os.urandom(16)
                self.cipher = Cipher(uuid_key, nonce)
                
                self.writer.write(nonce)
                self.writer.write(self.cipher.process(make_handshake(sni)))
                await self.writer.drain()
                
                self.connected = True
                self.reader_task = asyncio.create_task(self._reader_loop())
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
                    stream_id, length = struct.unpack('>IH', buf[:6])
                    if len(buf) < 6 + length:
                        break
                    
                    data = buf[6:6 + length]
                    buf = buf[6 + length:]
                    
                    if stream_id in self.streams:
                        if length == 0:
                            await self.streams[stream_id].put(None)
                        else:
                            await self.streams[stream_id].put(data)
                            
        except Exception:
            pass
        finally:
            self.connected = False
            for q in list(self.streams.values()):
                try:
                    await q.put(None)
                except Exception:
                    pass

    async def send_frame(self, stream_id, data):
        async with self.write_lock:
            header = struct.pack('>IH', stream_id, len(data))
            self.writer.write(self.cipher.process(header + data))
            await self.writer.drain()

    async def new_stream(self):
        async with self.lock:
            self.stream_counter += 1
            stream_id = self.stream_counter
            self.streams[stream_id] = asyncio.Queue()
            return stream_id

    async def close_stream(self, stream_id):
        try:
            await self.send_frame(stream_id, b'')
        except Exception:
            pass
        self.streams.pop(stream_id, None)

    def close(self):
        self.connected = False
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        self.streams.clear()
        self.stream_counter = 0


mux = MultiplexClient()


async def proxy_handler(local_reader, local_writer):
    stream_id = None
    try:
        if not mux.connected:
            if not await mux.connect(SERVER_IP, SERVER_PORT, VLESS_UUID, REALITY_SNI):
                local_writer.close()
                return

        stream_id = await mux.new_stream()
        
        async def to_remote():
            try:
                while True:
                    data = await local_reader.read(32768)
                    if not data:
                        break
                    await mux.send_frame(stream_id, data)
            except Exception:
                pass

        async def to_local():
            try:
                queue = mux.streams.get(stream_id)
                if not queue:
                    return
                while True:
                    data = await queue.get()
                    if data is None:
                        break
                    local_writer.write(data)
                    await local_writer.drain()
            except Exception:
                pass

        await asyncio.gather(to_remote(), to_local())
        
    except Exception:
        pass
    finally:
        if stream_id:
            await mux.close_stream(stream_id)
        try:
            local_writer.close()
        except Exception:
            pass


def set_system_proxy(enable):
    if sys.platform == 'win32':
        import winreg
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                0, winreg.KEY_ALL_ACCESS
            )
            if enable:
                winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, f'127.0.0.1:{PROXY_PORT}')
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
                print(f'[+] System proxy: 127.0.0.1:{PROXY_PORT}')
            else:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
                print('[+] Proxy disabled')
            winreg.CloseKey(key)
        except Exception as e:
            print(f'[-] Registry error: {e}')
            
    elif sys.platform in ('linux', 'darwin'):
        proxy = f'http://127.0.0.1:{PROXY_PORT}'
        if enable:
            os.environ['http_proxy'] = proxy
            os.environ['https_proxy'] = proxy
            os.environ['HTTP_PROXY'] = proxy
            os.environ['HTTPS_PROXY'] = proxy
            if os.system('which gsettings > /dev/null 2>&1') == 0:
                os.system("gsettings set org.gnome.system.proxy mode 'manual' 2>/dev/null")
                os.system("gsettings set org.gnome.system.proxy.http host '127.0.0.1' 2>/dev/null")
                os.system(f"gsettings set org.gnome.system.proxy.http port {PROXY_PORT} 2>/dev/null")
                os.system("gsettings set org.gnome.system.proxy.https host '127.0.0.1' 2>/dev/null")
                os.system(f"gsettings set org.gnome.system.proxy.https port {PROXY_PORT} 2>/dev/null")
            print(f'[+] Proxy: {proxy}')
        else:
            for v in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
                os.environ.pop(v, None)
            if os.system('which gsettings > /dev/null 2>&1') == 0:
                os.system("gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null")
            print('[+] Proxy disabled')


def show_banner():
    print('''
╔══════════════════════════════════════════════════╗
║                                                  ║
║     ██╗   ██╗██╗     ███████╗███████╗███████╗    ║
║     ██║   ██║██║     ██╔════╝██╔════╝██╔════╝    ║
║     ██║   ██║██║     █████╗  ███████╗███████╗    ║
║     ╚██╗ ██╔╝██║     ██╔══╝  ╚════██║╚════██║    ║
║      ╚████╔╝ ███████╗███████╗███████║███████║    ║
║       ╚═══╝  ╚══════╝╚══════╝╚══════╝╚══════╝    ║
║                                                  ║
║          Reality VPN Client v2.0                 ║
║                                                  ║
╚══════════════════════════════════════════════════╝
''')


def get_config():
    global SERVER_IP, SERVER_PORT, VLESS_UUID, REALITY_SNI
    
    if len(sys.argv) == 5:
        try:
            SERVER_IP = sys.argv[1]
            SERVER_PORT = int(sys.argv[2])
            VLESS_UUID = sys.argv[3]
            REALITY_SNI = sys.argv[4]
            return True
        except ValueError:
            print('[-] Port must be a number')
            return False
    elif len(sys.argv) > 1:
        print('Usage: client.py <server_ip> <port> <uuid> <sni>')
        return False
    
    show_banner()
    
    print('=' * 50)
    print('         Connection Configuration')
    print('=' * 50)
    
    while True:
        ip_in = input('\n[?] Server IP: ').strip()
        if not ip_in:
            print('    [-] Server IP is required')
            continue
        parts = ip_in.split('.')
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            SERVER_IP = ip_in
            print(f'    [+] Server: {SERVER_IP}')
            break
        print('    [-] Invalid IP format (e.g., 192.168.1.1)')
    
    while True:
        port_in = input('[?] Port [4433]: ').strip()
        if not port_in:
            SERVER_PORT = 4433
            break
        if port_in.isdigit() and 1 <= int(port_in) <= 65535:
            SERVER_PORT = int(port_in)
            break
        print('    [-] Invalid port (1-65535)')
    print(f'    [+] Port: {SERVER_PORT}')
    
    while True:
        uuid_in = input('[?] UUID (secret key): ').strip()
        if uuid_in:
            VLESS_UUID = uuid_in
            print(f'    [+] UUID: {VLESS_UUID[:20]}{"..." if len(VLESS_UUID) > 20 else ""}')
            break
        print('    [-] UUID is required')
    
    sni_in = input('[?] SNI [www.microsoft.com]: ').strip()
    if sni_in:
        REALITY_SNI = sni_in
    print(f'    [+] SNI: {REALITY_SNI}')
    
    print('\n' + '=' * 50)
    return True


async def test_connection():
    print('\n[*] Testing connection...')
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(SERVER_IP, SERVER_PORT), timeout=5
        )
        nonce = os.urandom(16)
        cipher = Cipher(VLESS_UUID, nonce)
        writer.write(nonce)
        writer.write(cipher.process(make_handshake(REALITY_SNI)))
        await writer.drain()
        await asyncio.sleep(0.3)
        writer.close()
        print('[+] Connection successful!')
        return True
    except asyncio.TimeoutError:
        print('[-] Connection timeout')
        return False
    except ConnectionRefusedError:
        print('[-] Connection refused')
        return False
    except Exception as e:
        print(f'[-] Connection failed: {e}')
        return False


async def main():
    if not get_config():
        return

    if not await test_connection():
        return

    print(f'''
╔══════════════════════════════════════════════════╗
║               VPN Client Ready                   ║
╠══════════════════════════════════════════════════╣
║  Server:     {SERVER_IP}:{SERVER_PORT:<30} ║
║  Local:      127.0.0.1:{PROXY_PORT:<28} ║
║  Status:     CONNECTED                           ║
╚══════════════════════════════════════════════════╝
''')

    if not await mux.connect(SERVER_IP, SERVER_PORT, VLESS_UUID, REALITY_SNI):
        print('[-] Failed to establish tunnel')
        return

    try:
        server = await asyncio.start_server(proxy_handler, '0.0.0.0', PROXY_PORT)
        print(f'[+] HTTP Proxy on 0.0.0.0:{PROXY_PORT}')
    except OSError as e:
        print(f'[-] Port {PROXY_PORT} busy: {e}')
        return

    set_system_proxy(True)
    
    print('\n[*] VPN is active. Press Ctrl+C to disconnect.\n')

    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        set_system_proxy(False)
        mux.close()
        server.close()
        print('\n[+] Disconnected')


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[!] Interrupted')
        set_system_proxy(False)
