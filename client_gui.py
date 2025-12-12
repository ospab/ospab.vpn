#!/usr/bin/env python3
import asyncio
import hashlib
import os
import random
import socket
import struct
import sys
import threading

if sys.platform == 'win32':
    import ctypes
    ctypes.windll.kernel32.FreeConsole()

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
        self.server_ip = ''
        self.server_port = 4433
        self.uuid = ''
        self.sni = 'www.microsoft.com'

    async def connect(self):
        async with self.lock:
            if self.connected:
                return True
            
            try:
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(self.server_ip, self.server_port), timeout=10
                )
                
                sock = self.writer.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
                
                nonce = os.urandom(16)
                self.cipher = Cipher(self.uuid, nonce)
                
                self.writer.write(nonce)
                self.writer.write(self.cipher.process(make_handshake(self.sni)))
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


class VPNClient:
    def __init__(self):
        self.mux = MultiplexClient()
        self.proxy_server = None
        self.loop = None
        self.running = False
        
    @property
    def server_ip(self):
        return self.mux.server_ip
    
    @server_ip.setter
    def server_ip(self, value):
        self.mux.server_ip = value
        
    @property
    def server_port(self):
        return self.mux.server_port
    
    @server_port.setter
    def server_port(self, value):
        self.mux.server_port = value
        
    @property
    def uuid(self):
        return self.mux.uuid
    
    @uuid.setter
    def uuid(self, value):
        self.mux.uuid = value
        
    @property
    def sni(self):
        return self.mux.sni
    
    @sni.setter
    def sni(self, value):
        self.mux.sni = value
        
    @property
    def connected(self):
        return self.mux.connected

    async def proxy_handler(self, local_reader, local_writer):
        stream_id = None
        try:
            if not self.mux.connected:
                if not await self.mux.connect():
                    local_writer.close()
                    return

            stream_id = await self.mux.new_stream()
            
            async def to_remote():
                try:
                    while True:
                        data = await local_reader.read(32768)
                        if not data:
                            break
                        await self.mux.send_frame(stream_id, data)
                except Exception:
                    pass

            async def to_local():
                try:
                    queue = self.mux.streams.get(stream_id)
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
                await self.mux.close_stream(stream_id)
            try:
                local_writer.close()
            except Exception:
                pass

    async def test_connection(self):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.server_ip, self.server_port), timeout=5
            )
            nonce = os.urandom(16)
            cipher = Cipher(self.uuid, nonce)
            writer.write(nonce)
            writer.write(cipher.process(make_handshake(self.sni)))
            await writer.drain()
            await asyncio.sleep(0.2)
            writer.close()
            return True
        except Exception:
            return False

    async def start_proxy(self):
        if not await self.mux.connect():
            raise ConnectionError("Failed to connect")
        
        self.proxy_server = await asyncio.start_server(
            self.proxy_handler, '0.0.0.0', PROXY_PORT
        )
        self.running = True
        await self.proxy_server.serve_forever()

    def stop_proxy(self):
        self.running = False
        if self.proxy_server:
            self.proxy_server.close()
        self.mux.close()


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
            else:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except Exception:
            pass
    else:
        proxy = f'http://127.0.0.1:{PROXY_PORT}'
        if enable:
            os.environ['http_proxy'] = proxy
            os.environ['https_proxy'] = proxy
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


def validate_ip(value):
    return all(c in '0123456789.' for c in value)

def validate_port(value):
    return value.isdigit() or value == ''

def validate_sni(value):
    return all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for c in value)

def validate_uuid(value):
    return all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in value)


def run_tui():
    import curses
    
    client = VPNClient()
    status = "Disconnected"
    log_messages = []
    current_step = 0
    
    def log(msg):
        log_messages.append(msg)
        if len(log_messages) > 8:
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
    
    def draw_box(stdscr, y, x, h, w, title=""):
        max_h, max_w = stdscr.getmaxyx()
        if y + h >= max_h or x + w >= max_w or y < 0 or x < 0:
            return
        try:
            stdscr.addch(y, x, curses.ACS_ULCORNER)
            stdscr.addch(y, x + w - 1, curses.ACS_URCORNER)
            stdscr.addch(y + h - 1, x, curses.ACS_LLCORNER)
            stdscr.addch(y + h - 1, x + w - 1, curses.ACS_LRCORNER)
            for i in range(1, w - 1):
                stdscr.addch(y, x + i, curses.ACS_HLINE)
                stdscr.addch(y + h - 1, x + i, curses.ACS_HLINE)
            for i in range(1, h - 1):
                stdscr.addch(y + i, x, curses.ACS_VLINE)
                stdscr.addch(y + i, x + w - 1, curses.ACS_VLINE)
            if title:
                stdscr.addstr(y, x + 2, f" {title} ")
        except curses.error:
            pass
    
    def wizard_step(stdscr, step):
        nonlocal current_step
        
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLUE)
        
        title = "ospab.vpn setup"
        stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(1, max(0, (w - len(title)) // 2), title)
        stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
        
        progress = f"Step {step + 1}/4"
        bar = "█" * (step + 1) + "░" * (3 - step)
        stdscr.attron(curses.color_pair(2))
        stdscr.addstr(3, 2, f"{progress} [{bar}]")
        stdscr.attroff(curses.color_pair(2))
        
        draw_box(stdscr, 5, 1, 8, min(w - 2, 52), "configuration")
        
        if step == 0:
            stdscr.addstr(7, 4, "enter your vpn server ip address:")
            result = get_filtered_input(stdscr, 9, 4, "ip: ", validate_ip)
            if result:
                parts = result.split('.')
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    client.server_ip = result
                    return True
            return False
            
        elif step == 1:
            stdscr.addstr(7, 4, "enter server port:")
            result = get_filtered_input(stdscr, 9, 4, "port: ", validate_port, "4433")
            try:
                port = int(result)
                if 1 <= port <= 65535:
                    client.server_port = port
                    return True
            except ValueError:
                pass
            return False
            
        elif step == 2:
            stdscr.addstr(7, 4, "enter your uuid (secret key):")
            result = get_filtered_input(stdscr, 9, 4, "uuid: ", validate_uuid)
            if result:
                client.uuid = result
                return True
            return False
            
        elif step == 3:
            stdscr.addstr(7, 4, "enter sni (camouflage domain):")
            result = get_filtered_input(stdscr, 9, 4, "sni: ", validate_sni, "www.microsoft.com")
            client.sni = result if result else "www.microsoft.com"
            return True
        
        return False
    
    def run_wizard(stdscr):
        for step in range(4):
            while not wizard_step(stdscr, step):
                stdscr.addstr(12, 4, "invalid input! try again...")
                stdscr.refresh()
                stdscr.getch()
        return True
    
    def main_loop(stdscr):
        nonlocal status
        
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_GREEN)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.curs_set(0)
        stdscr.nodelay(False)
        
        if not run_wizard(stdscr):
            return
        
        log("checking connection...")
        stdscr.clear()
        stdscr.addstr(5, 2, "verifying server connection...")
        stdscr.refresh()
        
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(client.test_connection())
        loop.close()
        
        if result:
            log("server reachable!")
            status = "ready"
        else:
            log("warning: server unreachable")
            status = "offline"
        
        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            
            if h < 20 or w < 50:
                stdscr.addstr(0, 0, "terminal too small!")
                stdscr.addstr(1, 0, f"need: 50x20, have: {w}x{h}")
                stdscr.addstr(2, 0, "resize and press any key...")
                stdscr.refresh()
                stdscr.getch()
                continue
            
            try:
                box_width = min(w - 2, 52)
                
                ascii_art = [
                    "██╗   ██╗██╗     ███████╗███████╗███████╗",
                    "██║   ██║██║     ██╔════╝██╔════╝██╔════╝",
                    "██║   ██║██║     █████╗  ███████╗███████╗",
                    "╚██╗ ██╔╝██║     ██╔══╝  ╚════██║╚════██║",
                    " ╚████╔╝ ███████╗███████╗███████║███████║",
                    "  ╚═══╝  ╚══════╝╚══════╝╚══════╝╚══════╝",
                ]
            
                stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                for i, line in enumerate(ascii_art):
                    x = max(0, (w - len(line)) // 2)
                    if x + len(line) < w:
                        stdscr.addstr(1 + i, x, line)
                stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
                
                subtitle = "ospab.vpn v2.0"
                stdscr.addstr(8, max(0, (w - len(subtitle)) // 2), subtitle)
                
                draw_box(stdscr, 10, 1, 6, box_width, "status")
                
                if client.connected:
                    stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
                    stdscr.addstr(12, 4, "● connected")
                    stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
                else:
                    stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
                    stdscr.addstr(12, 4, "○ disconnected")
                    stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
                
                stdscr.addstr(14, 4, f"server: {client.server_ip}:{client.server_port}")
                
                draw_box(stdscr, 17, 1, 5, box_width, "connection info")
                stdscr.addstr(19, 4, f"proxy: 127.0.0.1:{PROXY_PORT}")
                uuid_short = client.uuid[:16] + "..." if len(client.uuid) > 16 else client.uuid
                stdscr.addstr(20, 4, f"uuid: {uuid_short}")
                
                draw_box(stdscr, 23, 1, 5, box_width, "menu")
                
                if not client.connected:
                    stdscr.attron(curses.color_pair(2))
                    stdscr.addstr(25, 4, "[c] connect")
                    stdscr.attroff(curses.color_pair(2))
                else:
                    stdscr.attron(curses.color_pair(3))
                    stdscr.addstr(25, 4, "[d] disconnect")
                    stdscr.attroff(curses.color_pair(3))
                
                menu_rest = "[r] reconfigure   [q] quit"
                stdscr.addstr(26, 4, menu_rest[:box_width - 6])
                
                if log_messages and h > 34:
                    draw_box(stdscr, 29, 1, min(6, len(log_messages) + 2), box_width, "log")
                    for i, msg in enumerate(log_messages[-4:]):
                        if 30 + i < h - 1:
                            stdscr.addstr(30 + i, 4, msg[:box_width - 6])
            
            except curses.error:
                pass
            
            stdscr.refresh()
            key = stdscr.getch()
            
            if key == ord('c') or key == ord('C'):
                if not client.connected:
                    log("connecting...")
                    stdscr.refresh()
                    
                    def run_vpn():
                        nonlocal status
                        try:
                            client.loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(client.loop)
                            set_system_proxy(True)
                            status = "connected"
                            log("vpn tunnel established!")
                            client.loop.run_until_complete(client.start_proxy())
                        except Exception as err:
                            status = "error"
                            log(f"error: {str(err)[:30]}")
                            set_system_proxy(False)
                    
                    thread = threading.Thread(target=run_vpn, daemon=True)
                    thread.start()
                    
            elif key == ord('d') or key == ord('D'):
                if client.connected:
                    client.stop_proxy()
                    set_system_proxy(False)
                    status = "disconnected"
                    log("disconnected")
                    
            elif key == ord('r') or key == ord('R'):
                if client.connected:
                    client.stop_proxy()
                    set_system_proxy(False)
                run_wizard(stdscr)
                log("configuration updated")
                    
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
    wizard_complete = [False]
    
    def show_wizard():
        wizard = tk.Toplevel()
        wizard.title("VPN Setup Wizard")
        wizard.geometry("500x400")
        wizard.resizable(False, False)
        wizard.transient()
        wizard.grab_set()
        
        step = [0]
        
        header = tk.Frame(wizard, bg='#2d3436', height=80)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        title_label = tk.Label(header, text="🔐 ospab.vpn", 
                               font=('Segoe UI', 18, 'bold'), fg='white', bg='#2d3436')
        title_label.pack(pady=10)
        
        step_label = tk.Label(header, text="step 1/4: server ip", 
                              font=('Segoe UI', 10), fg='#b2bec3', bg='#2d3436')
        step_label.pack()
        
        progress_frame = tk.Frame(wizard, height=8, bg='#dfe6e9')
        progress_frame.pack(fill='x')
        
        progress_bar = tk.Frame(progress_frame, height=8, bg='#0984e3', width=125)
        progress_bar.pack(side='left')
        
        content = tk.Frame(wizard, padx=40, pady=30)
        content.pack(fill='both', expand=True)
        
        prompt_label = tk.Label(content, text="enter your vpn server ip address:", 
                                font=('Segoe UI', 12))
        prompt_label.pack(anchor='w', pady=(0, 10))
        
        allowed_chars = {
            'ip': '0123456789.',
            'port': '0123456789',
            'uuid': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_',
            'sni': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-'
        }
        current_filter = ['ip']
        
        entry_var = tk.StringVar()
        entry = ttk.Entry(content, textvariable=entry_var, font=('Segoe UI', 14), width=35)
        entry.pack(pady=10)
        entry.focus()
        
        def filter_paste(event):
            try:
                clipboard = wizard.clipboard_get()
                chars = allowed_chars[current_filter[0]]
                filtered = ''.join(c for c in clipboard if c in chars)
                if filtered:
                    entry.insert('insert', filtered)
                return 'break'
            except Exception:
                return 'break'
        
        def filter_key(event):
            if event.keysym in ('BackSpace', 'Delete', 'Left', 'Right', 'Home', 'End', 'Tab', 'Return'):
                return
            if event.state & 4:  # Ctrl
                return
            char = event.char
            if char and char not in allowed_chars[current_filter[0]]:
                return 'break'
        
        entry.bind('<Control-v>', filter_paste)
        entry.bind('<Control-V>', filter_paste)
        entry.bind('<KeyPress>', filter_key)
        
        error_label = tk.Label(content, text="", font=('Segoe UI', 9), fg='red')
        error_label.pack()
        
        btn_frame = tk.Frame(content)
        btn_frame.pack(side='bottom', pady=20)
        
        steps_config = [
            {"title": "step 1/4: server ip", "prompt": "enter your vpn server ip address:",
             "filter": "ip", "default": ""},
            {"title": "step 2/4: port", "prompt": "enter server port:",
             "filter": "port", "default": "4433"},
            {"title": "step 3/4: uuid", "prompt": "enter your uuid (secret key):",
             "filter": "uuid", "default": ""},
            {"title": "step 4/4: sni", "prompt": "enter sni (camouflage domain):",
             "filter": "sni", "default": "www.microsoft.com"},
        ]
        
        values = ["", "4433", "", "www.microsoft.com"]
        
        def update_step():
            config = steps_config[step[0]]
            step_label.config(text=config["title"])
            prompt_label.config(text=config["prompt"])
            entry_var.set(values[step[0]])
            current_filter[0] = config["filter"]
            progress_bar.config(width=125 * (step[0] + 1))
            error_label.config(text="")
            
            if step[0] > 0:
                back_btn.config(state='normal')
            else:
                back_btn.config(state='disabled')
                
            if step[0] == 3:
                next_btn.config(text="finish ✓")
            else:
                next_btn.config(text="next →")
        
        def next_step():
            val = entry_var.get().strip()
            
            if step[0] == 0:
                if not val:
                    error_label.config(text="server ip is required")
                    return
                parts = val.split('.')
                if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    error_label.config(text="invalid ip format")
                    return
                client.server_ip = val
                
            elif step[0] == 1:
                port = int(val) if val else 4433
                if port < 1 or port > 65535:
                    error_label.config(text="port must be 1-65535")
                    return
                client.server_port = port
                
            elif step[0] == 2:
                if not val:
                    error_label.config(text="uuid is required")
                    return
                client.uuid = val
                
            elif step[0] == 3:
                client.sni = val if val else "www.microsoft.com"
                wizard_complete[0] = True
                wizard.destroy()
                return
            
            values[step[0]] = val
            step[0] += 1
            update_step()
        
        def prev_step():
            if step[0] > 0:
                values[step[0]] = entry_var.get().strip()
                step[0] -= 1
                update_step()
        
        back_btn = ttk.Button(btn_frame, text="← back", command=prev_step, state='disabled')
        back_btn.pack(side='left', padx=5)
        
        next_btn = ttk.Button(btn_frame, text="next →", command=next_step)
        next_btn.pack(side='left', padx=5)
        
        wizard.bind('<Return>', lambda e: next_step())
        
        wizard.wait_window()
        return wizard_complete[0]
    
    root = tk.Tk()
    root.title("ospab.vpn")
    root.geometry("480x520")
    root.resizable(False, False)
    root.configure(bg='#f5f6fa')
    
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('TButton', font=('Segoe UI', 10), padding=10)
    style.configure('Accent.TButton', font=('Segoe UI', 11, 'bold'))
    style.configure('TLabel', background='#f5f6fa')
    
    header_frame = tk.Frame(root, bg='#2d3436', height=100)
    header_frame.pack(fill='x')
    header_frame.pack_propagate(False)
    
    logo_text = tk.Label(header_frame, text="🔐 ospab.vpn", 
                         font=('Segoe UI', 20, 'bold'), fg='white', bg='#2d3436')
    logo_text.pack(pady=15)
    
    subtitle = tk.Label(header_frame, text="secure vpn client v2.0",
                        font=('Segoe UI', 10), fg='#b2bec3', bg='#2d3436')
    subtitle.pack()
    
    status_frame = tk.Frame(root, bg='#f5f6fa', pady=15)
    status_frame.pack(fill='x')
    
    status_var = tk.StringVar(value="● disconnected")
    status_label = tk.Label(status_frame, textvariable=status_var, 
                            font=('Segoe UI', 14, 'bold'), fg='#e74c3c', bg='#f5f6fa')
    status_label.pack()
    
    info_frame = tk.LabelFrame(root, text="connection details", 
                               font=('Segoe UI', 10), bg='#f5f6fa', padx=15, pady=10)
    info_frame.pack(fill='x', padx=20, pady=10)
    
    server_var = tk.StringVar(value="not configured")
    tk.Label(info_frame, text="server:", font=('Segoe UI', 10), bg='#f5f6fa').grid(row=0, column=0, sticky='w')
    tk.Label(info_frame, textvariable=server_var, font=('Segoe UI', 10, 'bold'), bg='#f5f6fa').grid(row=0, column=1, sticky='w', padx=10)
    
    proxy_label = tk.Label(info_frame, text="local proxy:", font=('Segoe UI', 10), bg='#f5f6fa')
    proxy_label.grid(row=1, column=0, sticky='w')
    tk.Label(info_frame, text=f"127.0.0.1:{PROXY_PORT}", font=('Segoe UI', 10, 'bold'), bg='#f5f6fa').grid(row=1, column=1, sticky='w', padx=10)
    
    tk.Label(info_frame, text="uuid:", font=('Segoe UI', 10), bg='#f5f6fa').grid(row=2, column=0, sticky='w')
    uuid_var = tk.StringVar(value="---")
    tk.Label(info_frame, textvariable=uuid_var, font=('Segoe UI', 10), bg='#f5f6fa').grid(row=2, column=1, sticky='w', padx=10)
    
    btn_frame = tk.Frame(root, bg='#f5f6fa', pady=15)
    btn_frame.pack()
    
    def update_info():
        server_var.set(f"{client.server_ip}:{client.server_port}")
        uuid_display = client.uuid[:20] + "..." if len(client.uuid) > 20 else client.uuid
        uuid_var.set(uuid_display)
    
    def on_connect():
        if client.running:
            client.stop_proxy()
            set_system_proxy(False)
            status_var.set("● disconnected")
            status_label.config(fg='#e74c3c')
            connect_btn.config(text="🚀 connect")
            return
        
        if not client.server_ip or not client.uuid:
            if not show_wizard():
                return
            update_info()
        
        status_var.set("● connecting...")
        status_label.config(fg='#f39c12')
        root.update()
        
        def run_vpn():
            try:
                client.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(client.loop)
                
                if not client.loop.run_until_complete(client.test_connection()):
                    root.after(0, lambda: status_var.set("● connection failed"))
                    root.after(0, lambda: status_label.config(fg='#e74c3c'))
                    root.after(0, lambda: messagebox.showerror("error", "could not connect to server"))
                    return
                
                set_system_proxy(True)
                root.after(0, lambda: status_var.set("● connected"))
                root.after(0, lambda: status_label.config(fg='#27ae60'))
                root.after(0, lambda: connect_btn.config(text="🛑 disconnect"))
                client.loop.run_until_complete(client.start_proxy())
            except Exception as err:
                root.after(0, lambda: status_var.set("● error"))
                root.after(0, lambda: status_label.config(fg='#e74c3c'))
                set_system_proxy(False)
        
        thread = threading.Thread(target=run_vpn, daemon=True)
        thread.start()
    
    def on_configure():
        if client.running:
            messagebox.showwarning("warning", "disconnect first before reconfiguring")
            return
        if show_wizard():
            update_info()
            do_auto_check()
    
    def do_auto_check():
        status_var.set("● checking...")
        status_label.config(fg='#f39c12')
        root.update()
        
        def check_thread():
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(client.test_connection())
            loop.close()
            
            if result:
                root.after(0, lambda: status_var.set("● ready"))
                root.after(0, lambda: status_label.config(fg='#27ae60'))
            else:
                root.after(0, lambda: status_var.set("● offline"))
                root.after(0, lambda: status_label.config(fg='#e74c3c'))
        
        threading.Thread(target=check_thread, daemon=True).start()
    
    connect_btn = ttk.Button(btn_frame, text="🚀 connect", command=on_connect, width=20, style='Accent.TButton')
    connect_btn.pack(pady=5)
    
    sub_btn_frame = tk.Frame(btn_frame, bg='#f5f6fa')
    sub_btn_frame.pack(pady=5)
    
    ttk.Button(sub_btn_frame, text="⚙️ configure", command=on_configure, width=12).pack(side='left', padx=5)
    
    footer = tk.Label(root, text="press connect to setup or use existing configuration",
                      font=('Segoe UI', 9), fg='gray', bg='#f5f6fa')
    footer.pack(side='bottom', pady=10)
    
    def on_close():
        if client.running:
            client.stop_proxy()
            set_system_proxy(False)
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_close)
    
    if client.server_ip and client.uuid:
        update_info()
    
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
