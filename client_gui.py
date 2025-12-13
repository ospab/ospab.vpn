#!/usr/bin/env python3
"""ospab.vpn - GUI Client"""
import asyncio
import hashlib
import hmac
import os
import socket
import struct
import sys
import threading

if sys.platform == 'win32':
    import ctypes
    ctypes.windll.kernel32.FreeConsole()

PROXY_PORT = 10808


def derive_key(uuid_str):
    return hashlib.sha256(f"reality-auth-{uuid_str}".encode()).digest()


def build_client_hello(sni, uuid_str):
    nonce = os.urandom(16)
    auth_mac = hmac.new(derive_key(uuid_str), nonce, hashlib.sha256).digest()[:16]
    session_id = nonce + auth_mac
    
    sni_bytes = sni.encode()
    sni_ext = struct.pack('>HH', 0, len(sni_bytes) + 5)
    sni_ext += struct.pack('>H', len(sni_bytes) + 3) + b'\x00'
    sni_ext += struct.pack('>H', len(sni_bytes)) + sni_bytes
    
    extensions = sni_ext + struct.pack('>HH', 43, 3) + b'\x02\x03\x03'
    extensions += struct.pack('>HH', 10, 4) + b'\x00\x02\x00\x1d'
    extensions += struct.pack('>HH', 13, 4) + b'\x00\x02\x04\x03'
    extensions += struct.pack('>HH', 51, 36) + struct.pack('>H', 34)
    extensions += b'\x00\x1d\x00\x20' + os.urandom(32)
    
    hello = bytearray(b'\x03\x03') + os.urandom(32) + bytes([32]) + session_id
    hello += struct.pack('>H', 6) + b'\x13\x01\x13\x02\x13\x03'
    hello += b'\x01\x00' + struct.pack('>H', len(extensions)) + extensions
    
    handshake = bytes([0x01]) + len(hello).to_bytes(3, 'big') + hello
    return b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake, nonce


class Cipher:
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


class VPNClient:
    def __init__(self):
        self.reader = self.writer = self.cipher = None
        self.streams = {}
        self.counter = 0
        self.lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self.connected = False
        self.server = ''
        self.port = 443
        self.uuid = ''
        self.sni = 'www.microsoft.com'
        self.loop = None
        self.running = False

    async def connect(self):
        async with self.lock:
            if self.connected:
                return True
            try:
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(self.server, self.port), 10)
                self.writer.get_extra_info('socket').setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                
                hello, nonce = build_client_hello(self.sni, self.uuid)
                self.writer.write(hello)
                await self.writer.drain()
                
                resp = await asyncio.wait_for(self.reader.read(1024), 10)
                if len(resp) < 10 or resp[0] != 0x16:
                    return False
                
                self.cipher = Cipher(self.uuid, nonce)
                self.connected = True
                asyncio.create_task(self._reader())
                return True
            except Exception:
                return False

    async def _reader(self):
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
        self.connected = False

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

    async def proxy_handler(self, local_r, local_w):
        sid = None
        try:
            if not self.connected and not await self.connect():
                return local_w.close()
            sid = await self.new_stream()

            async def up():
                try:
                    while data := await local_r.read(32768):
                        await self.send(sid, data)
                except Exception:
                    pass

            async def down():
                q = self.streams.get(sid)
                if not q:
                    return
                try:
                    while True:
                        data = await q.get()
                        if data is None:
                            break
                        local_w.write(data)
                        await local_w.drain()
                except Exception:
                    pass

            await asyncio.gather(up(), down())
        except Exception:
            pass
        finally:
            if sid:
                self.streams.pop(sid, None)
            local_w.close()

    async def start(self):
        if not await self.connect():
            raise ConnectionError()
        self.running = True
        server = await asyncio.start_server(self.proxy_handler, '0.0.0.0', PROXY_PORT)
        await server.serve_forever()

    def stop(self):
        self.running = False
        self.connected = False
        if self.writer:
            self.writer.close()
        self.streams.clear()


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


def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox
    
    client = VPNClient()
    
    root = tk.Tk()
    root.title("ospab.vpn")
    root.geometry("400x450")
    root.resizable(False, False)
    root.configure(bg='#f5f6fa')
    
    # Header
    header = tk.Frame(root, bg='#2d3436', height=80)
    header.pack(fill='x')
    header.pack_propagate(False)
    tk.Label(header, text="🔐 ospab.vpn", font=('Segoe UI', 18, 'bold'), 
             fg='white', bg='#2d3436').pack(pady=20)
    
    # Config frame
    config = tk.LabelFrame(root, text="Configuration", font=('Segoe UI', 10), 
                           bg='#f5f6fa', padx=15, pady=10)
    config.pack(fill='x', padx=20, pady=15)
    
    fields = {}
    for i, (name, default) in enumerate([('Server IP', ''), ('Port', '443'), 
                                          ('UUID', ''), ('SNI', 'www.microsoft.com')]):
        tk.Label(config, text=name + ':', font=('Segoe UI', 10), bg='#f5f6fa').grid(row=i, column=0, sticky='w', pady=5)
        var = tk.StringVar(value=default)
        ttk.Entry(config, textvariable=var, width=30).grid(row=i, column=1, pady=5, padx=10)
        fields[name] = var
    
    # Status
    status_var = tk.StringVar(value="● Disconnected")
    status = tk.Label(root, textvariable=status_var, font=('Segoe UI', 12, 'bold'), 
                      fg='#e74c3c', bg='#f5f6fa')
    status.pack(pady=10)
    
    def on_connect():
        if client.running:
            client.stop()
            set_proxy(False)
            status_var.set("● Disconnected")
            status.config(fg='#e74c3c')
            btn.config(text="🚀 Connect")
            return
        
        client.server = fields['Server IP'].get().strip()
        client.port = int(fields['Port'].get() or 443)
        client.uuid = fields['UUID'].get().strip()
        client.sni = fields['SNI'].get().strip() or 'www.microsoft.com'
        
        if not client.server or not client.uuid:
            return messagebox.showerror("Error", "Server IP and UUID required")
        
        status_var.set("● Connecting...")
        status.config(fg='#f39c12')
        root.update()
        
        def run():
            try:
                client.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(client.loop)
                set_proxy(True)
                root.after(0, lambda: status_var.set("● Connected"))
                root.after(0, lambda: status.config(fg='#27ae60'))
                root.after(0, lambda: btn.config(text="🛑 Disconnect"))
                client.loop.run_until_complete(client.start())
            except Exception:
                root.after(0, lambda: status_var.set("● Error"))
                root.after(0, lambda: status.config(fg='#e74c3c'))
                set_proxy(False)
        
        threading.Thread(target=run, daemon=True).start()
    
    btn = ttk.Button(root, text="🚀 Connect", command=on_connect, width=20)
    btn.pack(pady=10)
    
    tk.Label(root, text=f"Proxy: 127.0.0.1:{PROXY_PORT}", font=('Segoe UI', 9), 
             fg='gray', bg='#f5f6fa').pack(side='bottom', pady=10)
    
    def on_close():
        if client.running:
            client.stop()
            set_proxy(False)
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == '__main__':
    run_gui()
