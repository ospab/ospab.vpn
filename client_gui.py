#!/usr/bin/env python3

import asyncio
import hashlib
import os
import random
import sys
import threading

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
    tls = b'\x16\x03\x01\x00\xfa'
    http = f'GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: keep-alive\r\n\r\n'.encode()
    pos = random.randint(10, len(http) - 5)
    return tls + http[:pos] + MAGIC_HEADER + http[pos:]


class VPNClient:
    def __init__(self):
        self.server_ip = ''
        self.server_port = 4433
        self.uuid = ''
        self.sni = 'www.microsoft.com'
        self.connected = False
        self.proxy_server = None
        self.loop = None
        
    async def connect(self):
        reader, writer = await asyncio.open_connection(self.server_ip, self.server_port)
        nonce = os.urandom(16)
        cipher = Cipher(self.uuid, nonce)
        writer.write(nonce)
        writer.write(cipher.process(make_handshake(self.sni)))
        await writer.drain()
        await asyncio.sleep(0.1)
        return reader, writer, cipher

    async def proxy_handler(self, local_reader, local_writer):
        remote_writer = None
        try:
            remote_reader, remote_writer, cipher = await self.connect()
            
            async def to_remote():
                try:
                    while True:
                        data = await local_reader.read(4096)
                        if not data:
                            break
                        remote_writer.write(cipher.process(data))
                        await remote_writer.drain()
                except Exception:
                    pass
                finally:
                    if remote_writer:
                        remote_writer.close()

            async def to_local():
                try:
                    while True:
                        data = await remote_reader.read(4096)
                        if not data:
                            break
                        local_writer.write(cipher.process(data))
                        await local_writer.drain()
                except Exception:
                    pass
                finally:
                    local_writer.close()

            await asyncio.gather(to_remote(), to_local())
        except Exception:
            if remote_writer:
                remote_writer.close()
            local_writer.close()

    async def test_connection(self):
        try:
            r, w, c = await asyncio.wait_for(self.connect(), timeout=5)
            w.write(c.process(b'PING'))
            await w.drain()
            resp = await asyncio.wait_for(r.read(64), timeout=5)
            w.close()
            return c.process(resp) == b'PONG'
        except Exception:
            return False

    async def start_proxy(self):
        self.proxy_server = await asyncio.start_server(
            self.proxy_handler, '0.0.0.0', PROXY_PORT
        )
        self.connected = True
        await self.proxy_server.serve_forever()

    def stop_proxy(self):
        if self.proxy_server:
            self.proxy_server.close()
        self.connected = False


def set_system_proxy(enable: bool):
    proxy_url = f'http://127.0.0.1:{PROXY_PORT}'
    
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
            else:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except Exception:
            pass
    else:
        if enable:
            os.environ['http_proxy'] = proxy_url
            os.environ['https_proxy'] = proxy_url
            if os.system('which gsettings > /dev/null 2>&1') == 0:
                os.system("gsettings set org.gnome.system.proxy mode 'manual' 2>/dev/null")
                os.system("gsettings set org.gnome.system.proxy.http host '127.0.0.1' 2>/dev/null")
                os.system(f"gsettings set org.gnome.system.proxy.http port {PROXY_PORT} 2>/dev/null")
                os.system("gsettings set org.gnome.system.proxy.https host '127.0.0.1' 2>/dev/null")
                os.system(f"gsettings set org.gnome.system.proxy.https port {PROXY_PORT} 2>/dev/null")
        else:
            os.environ.pop('http_proxy', None)
            os.environ.pop('https_proxy', None)
            if os.system('which gsettings > /dev/null 2>&1') == 0:
                os.system("gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null")


def validate_ip(value: str) -> bool:
    return all(c in '0123456789.' for c in value)

def validate_port(value: str) -> bool:
    return value.isdigit() or value == ''

def validate_sni(value: str) -> bool:
    return all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for c in value)

def validate_uuid(value: str) -> bool:
    return all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in value)


def run_tui():
    import curses
    
    client = VPNClient()
    status = "Disconnected"
    log_messages = []
    
    def log(msg):
        log_messages.append(msg)
        if len(log_messages) > 10:
            log_messages.pop(0)
    
    def get_filtered_input(win, y, x, prompt, validator, default=""):
        curses.echo()
        curses.curs_set(1)
        win.addstr(y, x, prompt)
        win.refresh()
        
        result = ""
        pos = x + len(prompt)
        
        while True:
            ch = win.getch()
            if ch == ord('\n') or ch == 10 or ch == 13:
                break
            elif ch == 27:
                result = ""
                break
            elif ch == curses.KEY_BACKSPACE or ch == 127 or ch == 8:
                if result:
                    result = result[:-1]
                    win.addstr(y, pos, result + " ")
                    win.move(y, pos + len(result))
            elif 32 <= ch <= 126:
                char = chr(ch)
                if validator(result + char):
                    result += char
                    win.addstr(y, pos, result)
            win.refresh()
        
        curses.noecho()
        curses.curs_set(0)
        return result if result else default
    
    def main_loop(stdscr):
        nonlocal status
        
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.curs_set(0)
        stdscr.nodelay(False)
        
        while True:
            stdscr.clear()
            _, w = stdscr.getmaxyx()
            
            title = "=== VLESS-Reality VPN Client ==="
            stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(1, max(0, (w - len(title)) // 2), title)
            stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
            
            status_color = curses.color_pair(2) if client.connected else curses.color_pair(3)
            stdscr.attron(status_color)
            stdscr.addstr(3, 2, f"Status: {status}")
            stdscr.attroff(status_color)
            
            stdscr.addstr(5, 2, f"Server: {client.server_ip or '---'}:{client.server_port}")
            uuid_display = client.uuid[:20] + '...' if len(client.uuid) > 20 else client.uuid or '---'
            stdscr.addstr(6, 2, f"UUID:   {uuid_display}")
            stdscr.addstr(7, 2, f"SNI:    {client.sni}")
            stdscr.addstr(8, 2, f"Proxy:  127.0.0.1:{PROXY_PORT}")
            
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(10, 2, "-" * 40)
            stdscr.attroff(curses.color_pair(4))
            
            menu = [
                "[1] Configure connection",
                "[2] Connect" if not client.connected else "[2] Disconnect",
                "[3] Test connection",
                "[Q] Quit"
            ]
            for i, item in enumerate(menu):
                stdscr.addstr(11 + i, 4, item)
            
            stdscr.addstr(16, 2, "Log:")
            for i, msg in enumerate(log_messages[-5:]):
                stdscr.addstr(17 + i, 4, msg[:w-6])
            
            stdscr.refresh()
            
            key = stdscr.getch()
            
            if key == ord('1'):
                stdscr.clear()
                stdscr.addstr(1, 2, "=== Configuration ===")
                stdscr.addstr(2, 2, "(Only valid characters allowed)")
                
                ip = get_filtered_input(stdscr, 4, 2, "Server IP (digits, dots): ", validate_ip)
                if not ip:
                    log("Error: IP required")
                    continue
                client.server_ip = ip
                    
                port_str = get_filtered_input(stdscr, 5, 2, "Port (digits only) [4433]: ", validate_port, "4433")
                try:
                    client.server_port = int(port_str)
                    if client.server_port < 1 or client.server_port > 65535:
                        raise ValueError()
                except ValueError:
                    log("Error: Invalid port (1-65535)")
                    continue
                
                uuid_val = get_filtered_input(stdscr, 6, 2, "UUID (alphanumeric, -, _): ", validate_uuid)
                if not uuid_val:
                    log("Error: UUID required")
                    continue
                client.uuid = uuid_val
                
                sni = get_filtered_input(stdscr, 7, 2, "SNI [www.microsoft.com]: ", validate_sni, "www.microsoft.com")
                client.sni = sni
                log("Configuration saved")
                
            elif key == ord('2'):
                if not client.connected:
                    if not client.server_ip or not client.uuid:
                        log("Error: Configure first")
                        continue
                    
                    status = "Connecting..."
                    stdscr.refresh()
                    
                    def run_vpn():
                        nonlocal status
                        try:
                            client.loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(client.loop)
                            
                            if not client.loop.run_until_complete(client.test_connection()):
                                status = "Auth failed"
                                log("Authentication failed")
                                return
                            
                            set_system_proxy(True)
                            status = "Connected"
                            log("Connected! Proxy active")
                            client.loop.run_until_complete(client.start_proxy())
                        except Exception as err:
                            status = "Error"
                            log(f"Error: {str(err)[:30]}")
                    
                    thread = threading.Thread(target=run_vpn, daemon=True)
                    thread.start()
                else:
                    client.stop_proxy()
                    set_system_proxy(False)
                    status = "Disconnected"
                    log("Disconnected")
                    
            elif key == ord('3'):
                if not client.server_ip or not client.uuid:
                    log("Error: Configure first")
                    continue
                
                status = "Testing..."
                stdscr.refresh()
                
                loop = asyncio.new_event_loop()
                result = loop.run_until_complete(client.test_connection())
                loop.close()
                
                if result:
                    log("Connection OK!")
                    status = "Test passed"
                else:
                    log("Connection failed")
                    status = "Test failed"
                    
            elif key == ord('q') or key == ord('Q'):
                if client.connected:
                    client.stop_proxy()
                    set_system_proxy(False)
                break
    
    curses.wrapper(main_loop)


def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox
    
    client = VPNClient()
    
    root = tk.Tk()
    root.title("VLESS-Reality VPN")
    root.geometry("420x380")
    root.resizable(False, False)
    
    style = ttk.Style()
    style.configure('TLabel', padding=5)
    style.configure('TEntry', padding=5)
    style.configure('TButton', padding=10)
    
    def vcmd_ip(value):
        if value == "":
            return True
        return all(c in '0123456789.' for c in value) and len(value) <= 15
    
    def vcmd_port(value):
        if value == "":
            return True
        return value.isdigit() and len(value) <= 5
    
    def vcmd_uuid(value):
        if value == "":
            return True
        return all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in value)
    
    def vcmd_sni(value):
        if value == "":
            return True
        return all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for c in value)
    
    validate_ip_cmd = root.register(vcmd_ip)
    validate_port_cmd = root.register(vcmd_port)
    validate_uuid_cmd = root.register(vcmd_uuid)
    validate_sni_cmd = root.register(vcmd_sni)
    
    var_ip = tk.StringVar()
    var_port = tk.StringVar(value="4433")
    var_uuid = tk.StringVar()
    var_sni = tk.StringVar(value="www.microsoft.com")
    var_status = tk.StringVar(value="Disconnected")
    
    header = ttk.Label(root, text="VLESS-Reality VPN Client", font=('Segoe UI', 14, 'bold'))
    header.pack(pady=10)
    
    frame = ttk.Frame(root)
    frame.pack(padx=20, pady=10, fill='x')
    
    ttk.Label(frame, text="Server IP:").grid(row=0, column=0, sticky='w')
    entry_ip = ttk.Entry(frame, textvariable=var_ip, width=30, 
                         validate='key', validatecommand=(validate_ip_cmd, '%P'))
    entry_ip.grid(row=0, column=1, pady=2)
    ttk.Label(frame, text="(digits, dots)", font=('Segoe UI', 8)).grid(row=0, column=2, padx=5)
    
    ttk.Label(frame, text="Port:").grid(row=1, column=0, sticky='w')
    entry_port = ttk.Entry(frame, textvariable=var_port, width=30,
                           validate='key', validatecommand=(validate_port_cmd, '%P'))
    entry_port.grid(row=1, column=1, pady=2)
    ttk.Label(frame, text="(1-65535)", font=('Segoe UI', 8)).grid(row=1, column=2, padx=5)
    
    ttk.Label(frame, text="UUID:").grid(row=2, column=0, sticky='w')
    entry_uuid = ttk.Entry(frame, textvariable=var_uuid, width=30,
                           validate='key', validatecommand=(validate_uuid_cmd, '%P'))
    entry_uuid.grid(row=2, column=1, pady=2)
    ttk.Label(frame, text="(a-z, 0-9, -, _)", font=('Segoe UI', 8)).grid(row=2, column=2, padx=5)
    
    ttk.Label(frame, text="SNI:").grid(row=3, column=0, sticky='w')
    entry_sni = ttk.Entry(frame, textvariable=var_sni, width=30,
                          validate='key', validatecommand=(validate_sni_cmd, '%P'))
    entry_sni.grid(row=3, column=1, pady=2)
    ttk.Label(frame, text="(hostname)", font=('Segoe UI', 8)).grid(row=3, column=2, padx=5)
    
    status_frame = ttk.Frame(root)
    status_frame.pack(pady=10)
    ttk.Label(status_frame, text="Status:").pack(side='left')
    status_label = ttk.Label(status_frame, textvariable=var_status, font=('Segoe UI', 10, 'bold'))
    status_label.pack(side='left', padx=5)
    
    ttk.Label(root, text=f"Local Proxy: 127.0.0.1:{PROXY_PORT}").pack()
    
    btn_frame = ttk.Frame(root)
    btn_frame.pack(pady=20)
    
    def on_connect():
        if client.connected:
            client.stop_proxy()
            set_system_proxy(False)
            var_status.set("Disconnected")
            btn_connect.config(text="Connect")
            return
        
        ip = var_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "Server IP required")
            return
        
        parts = ip.split('.')
        if len(parts) != 4:
            messagebox.showerror("Error", "Invalid IP format (e.g., 192.168.1.1)")
            return
        for part in parts:
            if not part or not part.isdigit() or int(part) > 255:
                messagebox.showerror("Error", "Invalid IP format")
                return
        
        if not var_uuid.get().strip():
            messagebox.showerror("Error", "UUID required")
            return
        
        try:
            port = int(var_port.get())
            if port < 1 or port > 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Invalid port (1-65535)")
            return
        
        client.server_ip = ip
        client.server_port = port
        client.uuid = var_uuid.get().strip()
        client.sni = var_sni.get().strip() or "www.microsoft.com"
        
        var_status.set("Connecting...")
        root.update()
        
        def run_vpn():
            try:
                client.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(client.loop)
                
                if not client.loop.run_until_complete(client.test_connection()):
                    root.after(0, lambda: var_status.set("Auth failed"))
                    root.after(0, lambda: messagebox.showerror("Error", "Authentication failed"))
                    return
                
                set_system_proxy(True)
                root.after(0, lambda: var_status.set("Connected"))
                root.after(0, lambda: btn_connect.config(text="Disconnect"))
                client.loop.run_until_complete(client.start_proxy())
            except Exception as err:
                error_msg = str(err)
                root.after(0, lambda: var_status.set("Error"))
                root.after(0, lambda m=error_msg: messagebox.showerror("Error", m))
        
        thread = threading.Thread(target=run_vpn, daemon=True)
        thread.start()
    
    def on_test():
        ip = var_ip.get().strip()
        if not ip or not var_uuid.get().strip():
            messagebox.showerror("Error", "Fill all fields first")
            return
        
        try:
            port = int(var_port.get())
            if port < 1 or port > 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Invalid port")
            return
        
        client.server_ip = ip
        client.server_port = port
        client.uuid = var_uuid.get().strip()
        client.sni = var_sni.get().strip() or "www.microsoft.com"
        
        var_status.set("Testing...")
        root.update()
        
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(client.test_connection())
        loop.close()
        
        if result:
            var_status.set("Test OK")
            messagebox.showinfo("Success", "Connection test passed!")
        else:
            var_status.set("Test failed")
            messagebox.showerror("Error", "Connection test failed")
    
    btn_connect = ttk.Button(btn_frame, text="Connect", command=on_connect, width=15)
    btn_connect.pack(side='left', padx=5)
    
    btn_test = ttk.Button(btn_frame, text="Test", command=on_test, width=10)
    btn_test.pack(side='left', padx=5)
    
    def on_close():
        if client.connected:
            client.stop_proxy()
            set_system_proxy(False)
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == '__main__':
    if sys.platform == 'win32':
        run_gui()
    elif sys.platform == 'darwin':
        run_gui()
    else:
        if os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'):
            try:
                import tkinter as _tk_test
                _tk_test.Tk().destroy()
                run_gui()
            except Exception:
                run_tui()
        else:
            run_tui()
