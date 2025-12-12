#!/usr/bin/env python3
"""VLESS-Reality VPN Client"""

import asyncio
import hashlib
import os
import random
import sys

# --- Configuration ---
SERVER_IP = os.environ.get('SERVER', '127.0.0.1')
SERVER_PORT = int(os.environ.get('PORT', 4433))
VLESS_UUID = os.environ.get('UUID', '')
REALITY_SNI = os.environ.get('SNI', 'www.microsoft.com')
MAGIC_HEADER = b'\x56\x4c\x45\x53'
PROXY_PORT = 10808


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


def make_handshake(sni: str) -> bytes:
    """Generate Reality handshake packet"""
    tls = b'\x16\x03\x01\x00\xfa'
    http = f'GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: keep-alive\r\n\r\n'.encode()
    pos = random.randint(10, len(http) - 5)
    return tls + http[:pos] + MAGIC_HEADER + http[pos:]


async def connect():
    """Establish encrypted connection to server"""
    reader, writer = await asyncio.open_connection(SERVER_IP, SERVER_PORT)
    
    nonce = os.urandom(16)
    cipher = Cipher(VLESS_UUID, nonce)
    
    writer.write(nonce)
    writer.write(cipher.process(make_handshake(REALITY_SNI)))
    await writer.drain()
    
    await asyncio.sleep(0.1)
    return reader, writer, cipher


async def proxy_handler(local_reader, local_writer):
    """Handle local proxy connection"""
    try:
        remote_reader, remote_writer, cipher = await connect()
        
        async def to_remote():
            try:
                while True:
                    data = await local_reader.read(4096)
                    if not data:
                        break
                    remote_writer.write(cipher.process(data))
                    await remote_writer.drain()
            except:
                pass
            finally:
                remote_writer.close()

        async def to_local():
            try:
                while True:
                    data = await remote_reader.read(4096)
                    if not data:
                        break
                    local_writer.write(cipher.process(data))
                    await local_writer.drain()
            except:
                pass
            finally:
                local_writer.close()

        await asyncio.gather(to_remote(), to_local())
        
    except Exception as e:
        print(f'Proxy error: {e}')
        local_writer.close()


def set_system_proxy(enable: bool):
    """Set/unset system proxy"""
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
                print(f'[+] System proxy enabled: 127.0.0.1:{PROXY_PORT}')
            else:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
                print('[+] System proxy disabled')
            winreg.CloseKey(key)
        except Exception as e:
            print(f'[-] Registry error: {e}')
            
    elif sys.platform == 'linux' or sys.platform == 'darwin':
        proxy_url = f'http://127.0.0.1:{PROXY_PORT}'
        
        if enable:
            # Set environment variables for current process children
            os.environ['http_proxy'] = proxy_url
            os.environ['https_proxy'] = proxy_url
            os.environ['HTTP_PROXY'] = proxy_url
            os.environ['HTTPS_PROXY'] = proxy_url
            
            # Try GNOME gsettings
            if os.system('which gsettings > /dev/null 2>&1') == 0:
                os.system("gsettings set org.gnome.system.proxy mode 'manual' 2>/dev/null")
                os.system(f"gsettings set org.gnome.system.proxy.http host '127.0.0.1' 2>/dev/null")
                os.system(f"gsettings set org.gnome.system.proxy.http port {PROXY_PORT} 2>/dev/null")
                os.system(f"gsettings set org.gnome.system.proxy.https host '127.0.0.1' 2>/dev/null")
                os.system(f"gsettings set org.gnome.system.proxy.https port {PROXY_PORT} 2>/dev/null")
                print(f'[+] GNOME proxy enabled')
            
            # Try KDE
            if os.path.exists(os.path.expanduser('~/.config/kioslaverc')):
                try:
                    with open(os.path.expanduser('~/.config/kioslaverc'), 'a') as f:
                        f.write(f'\n[Proxy Settings]\nProxyType=1\nhttpProxy=http://127.0.0.1 {PROXY_PORT}\nhttpsProxy=http://127.0.0.1 {PROXY_PORT}\n')
                    print('[+] KDE proxy configured')
                except:
                    pass
            
            print(f'[+] Proxy: {proxy_url}')
            print('[!] For terminal apps, run:')
            print(f'    export http_proxy={proxy_url} https_proxy={proxy_url}')
        else:
            os.environ.pop('http_proxy', None)
            os.environ.pop('https_proxy', None)
            os.environ.pop('HTTP_PROXY', None)
            os.environ.pop('HTTPS_PROXY', None)
            
            if os.system('which gsettings > /dev/null 2>&1') == 0:
                os.system("gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null")
            print('[+] Proxy disabled')


def get_config():
    """Get client configuration from args or interactive input"""
    global SERVER_IP, SERVER_PORT, VLESS_UUID, REALITY_SNI
    
    # CLI args: client.py <server_ip> <port> <uuid> <sni>
    if len(sys.argv) == 5:
        try:
            SERVER_IP = sys.argv[1]
            SERVER_PORT = int(sys.argv[2])
            VLESS_UUID = sys.argv[3]
            REALITY_SNI = sys.argv[4]
            return True
        except ValueError:
            print('[-] Error: port must be a number')
            return False
    elif len(sys.argv) > 1:
        print('[-] Error: provide all arguments or none')
        print('    Usage: client.py <server_ip> <port> <uuid> <sni>')
        print('    Example: client.py 1.2.3.4 4433 my-secret-key www.google.com')
        return False
    
    # Interactive input
    print('\n=== Client Configuration ===')
    
    ip_in = input('Server IP: ').strip()
    if not ip_in:
        print('[-] Server IP required')
        return False
    SERVER_IP = ip_in
    
    try:
        port_in = input('Port [4433]: ').strip()
        if port_in:
            SERVER_PORT = int(port_in)
    except ValueError:
        print('[-] Invalid port')
        return False
    
    uuid_in = input('UUID: ').strip()
    if not uuid_in:
        print('[-] UUID required')
        return False
    VLESS_UUID = uuid_in
    
    sni_in = input('SNI [www.microsoft.com]: ').strip()
    if sni_in:
        REALITY_SNI = sni_in
    
    return True


async def main():
    global SERVER_IP, SERVER_PORT, VLESS_UUID, REALITY_SNI
    
    if not get_config():
        return

    print(f'''
╔══════════════════════════════════════════╗
║         VLESS-Reality Client             ║
╠══════════════════════════════════════════╣
║  Server: {SERVER_IP}:{SERVER_PORT:<24}║
║  Proxy:  127.0.0.1:{PROXY_PORT:<23}║
╚══════════════════════════════════════════╝
''')

    # Test connection
    try:
        print('[*] Testing connection...')
        r, w, c = await asyncio.wait_for(connect(), timeout=5)
        w.write(c.process(b'PING'))
        await w.drain()
        resp = await asyncio.wait_for(r.read(64), timeout=5)
        if c.process(resp) == b'PONG':
            print('[+] Server authenticated')
        w.close()
    except Exception as e:
        print(f'[-] Connection failed: {e}')
        return

    # Start proxy
    try:
        server = await asyncio.start_server(proxy_handler, '0.0.0.0', PROXY_PORT)
        print(f'[+] HTTP Proxy listening on 0.0.0.0:{PROXY_PORT}')
    except OSError as e:
        print(f'[-] Port {PROXY_PORT} busy: {e}')
        return

    set_system_proxy(True)
    print('[*] Press Ctrl+C to stop\n')

    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        set_system_proxy(False)
        server.close()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[!] Stopped')
        set_system_proxy(False)
