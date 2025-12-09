# vless_reality_client_gui.py
# Enhanced GUI for VLESS-Reality Client
# Municipal Stage Cybersecurity Olympiad

import asyncio
import random
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import threading
from datetime import datetime
import hashlib
import os
import sys

# --- Configuration Defaults ---
DEFAULT_SERVER_IP = '127.0.0.1'
DEFAULT_SERVER_PORT = 4433
DEFAULT_SNI = "www.microsoft.com"
VLESS_MAGIC_HEADER = b'\x56\x4c\x45\x53'
CHUNK_SIZE = 50
KEEP_ALIVE_INTERVAL = 60

# --- Crypto Module ---
class StreamCipher:
    """
    ChaCha20-Poly1305 Mock (Stream Cipher).
    Uses SHA256(Key + Nonce + Counter) to generate keystream.
    """
    def __init__(self, key: str, nonce: bytes):
        self.key = key.encode() if key else b''
        self.nonce = nonce
        self.counter = 0
        self.buffer = b''

    def _refill_buffer(self):
        data = self.key + self.nonce + self.counter.to_bytes(8, 'big')
        self.buffer += hashlib.sha256(data).digest()
        self.counter += 1

    def encrypt(self, data: bytes) -> bytes:
        result = bytearray()
        for byte in data:
            if not self.buffer:
                self._refill_buffer()
            key_byte = self.buffer[0]
            self.buffer = self.buffer[1:]
            result.append(byte ^ key_byte)
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)

# --- GUI Application ---
class ModernVLESSClient:
    def __init__(self, root):
        self.root = root
        self.root.title("VLESS-Reality Secure Client")
        self.root.geometry("850x650")
        self.root.configure(bg="#1e1e1e")
        
        # Custom Fonts
        self.font_main = font.Font(family="Segoe UI", size=10)
        self.font_bold = font.Font(family="Segoe UI", size=10, weight="bold")
        self.font_header = font.Font(family="Segoe UI", size=16, weight="bold")
        self.font_mono = font.Font(family="Consolas", size=9)

        # State
        self.connected = False
        self.loop = None
        self.reader = None
        self.writer = None
        self.cipher = None
        self.keep_alive_task = None
        self.reader_task = None
        self.proxy_task = None
        self.local_proxy_server = None
        
        self._setup_styles()
        self._build_ui()
        
        self.log("Client initialized. Ready to connect.", "SYSTEM")

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Dark Theme Colors
        bg_dark = "#1e1e1e"
        fg_light = "#cccccc"
        accent = "#007acc"
        
        style.configure("TFrame", background=bg_dark)
        style.configure("TLabel", background=bg_dark, foreground=fg_light, font=self.font_main)
        style.configure("TButton", background=accent, foreground="white", borderwidth=0, font=self.font_bold)
        style.map("TButton", background=[('active', '#005f9e')])
        
        style.configure("Header.TLabel", font=self.font_header, foreground="white")

    def _build_ui(self):
        # Main Container
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Header Section
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(header_frame, text="VLESS-Reality", style="Header.TLabel").pack(side=tk.LEFT)
        
        self.status_var = tk.StringVar(value="DISCONNECTED")
        self.status_label = tk.Label(
            header_frame, 
            textvariable=self.status_var,
            bg="#1e1e1e",
            fg="#f44336", # Red
            font=("Segoe UI", 10, "bold")
        )
        self.status_label.pack(side=tk.RIGHT)

        # 2. Configuration Grid
        config_frame = tk.LabelFrame(
            main_frame, 
            text="Connection Settings",
            bg="#1e1e1e",
            fg="#cccccc",
            font=self.font_bold,
            padx=15, pady=15
        )
        config_frame.pack(fill=tk.X, pady=(0, 20))

        # Grid Layout for Config
        tk.Label(config_frame, text="Server Address:", bg="#1e1e1e", fg="#cccccc", font=self.font_main).grid(row=0, column=0, sticky="w", pady=5)
        self.entry_server = tk.Entry(config_frame, bg="#3c3c3c", fg="white", insertbackground="white", font=self.font_mono)
        self.entry_server.insert(0, f"{DEFAULT_SERVER_IP}:{DEFAULT_SERVER_PORT}")
        self.entry_server.grid(row=0, column=1, sticky="ew", padx=10)

        tk.Label(config_frame, text="Reality SNI:", bg="#1e1e1e", fg="#cccccc", font=self.font_main).grid(row=0, column=2, sticky="w", pady=5)
        self.entry_sni = tk.Entry(config_frame, bg="#3c3c3c", fg="white", insertbackground="white", font=self.font_mono)
        self.entry_sni.insert(0, DEFAULT_SNI)
        self.entry_sni.grid(row=0, column=3, sticky="ew", padx=10)

        tk.Label(config_frame, text="VLESS UUID:", bg="#1e1e1e", fg="#cccccc", font=self.font_main).grid(row=1, column=0, sticky="w", pady=5)
        self.entry_uuid = tk.Entry(config_frame, bg="#3c3c3c", fg="white", insertbackground="white", font=self.font_mono, width=40)
        self.entry_uuid.grid(row=1, column=1, columnspan=3, sticky="ew", padx=10)

        config_frame.columnconfigure(1, weight=1)
        config_frame.columnconfigure(3, weight=1)

        # 3. Actions
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(0, 20))

        self.btn_connect = tk.Button(
            action_frame, 
            text="CONNECT", 
            bg="#007acc", 
            fg="white", 
            font=self.font_bold,
            relief="flat",
            padx=20,
            pady=5,
            command=self.toggle_connection
        )
        self.btn_connect.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_link = tk.Button(
            action_frame, 
            text="GET LINK", 
            bg="#2d2d2d", 
            fg="white", 
            font=self.font_bold,
            relief="flat",
            padx=15,
            pady=5,
            command=self.generate_link
        )
        self.btn_link.pack(side=tk.LEFT)

        # 4. Terminal/Log
        log_frame = tk.LabelFrame(
            main_frame,
            text="Secure Terminal",
            bg="#1e1e1e",
            fg="#cccccc",
            font=self.font_bold,
            padx=5, pady=5
        )
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            bg="#0f0f0f",
            fg="#cccccc",
            insertbackground="white",
            font=self.font_mono,
            state='disabled'
        )
        self.log_area.pack(fill=tk.BOTH, expand=True)
        
        # Tags for coloring
        self.log_area.tag_config("SYSTEM", foreground="#569cd6")
        self.log_area.tag_config("ERROR", foreground="#f44336")
        self.log_area.tag_config("SUCCESS", foreground="#4caf50")
        self.log_area.tag_config("SEND", foreground="#ce9178")
        self.log_area.tag_config("RECV", foreground="#dcdcaa")
        self.log_area.tag_config("ENCRYPT", foreground="#c586c0")

        # 5. Input Area
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(10, 0))

        # Instruction Label
        tk.Label(
            input_frame, 
            text="Command Input (/help, /proxy, /global, /message <text>):", 
            bg="#1e1e1e", 
            fg="#888888", 
            font=("Segoe UI", 8)
        ).pack(anchor="w", pady=(0, 2))

        input_inner_frame = ttk.Frame(input_frame)
        input_inner_frame.pack(fill=tk.X)

        # Prompt Label
        tk.Label(
            input_inner_frame, 
            text=">", 
            bg="#1e1e1e", 
            fg="#007acc", 
            font=self.font_bold
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.entry_message = tk.Entry(
            input_inner_frame, 
            bg="#3c3c3c", 
            fg="white", 
            insertbackground="white", 
            font=self.font_mono
        )
        self.entry_message.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.entry_message.bind("<Return>", lambda e: self.send_message())

        self.btn_send = tk.Button(
            input_inner_frame,
            text="SEND",
            bg="#2d2d2d",
            fg="white",
            font=self.font_bold,
            relief="flat",
            padx=15,
            command=self.send_message,
            state="disabled"
        )
        self.btn_send.pack(side=tk.RIGHT)

    def log(self, message, tag="INFO"):
        self.log_area.config(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] ", "SYSTEM")
        self.log_area.insert(tk.END, f"[{tag}] {message}\n", tag)
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def generate_link(self):
        uuid = self.entry_uuid.get().strip()
        server = self.entry_server.get().strip()
        sni = self.entry_sni.get().strip()
        
        if not uuid or not server:
            messagebox.showerror("Error", "UUID and Server Address required!")
            return
            
        try:
            ip, port = server.split(':')
        except ValueError:
            messagebox.showerror("Error", "Invalid Server Address")
            return

        # Generate standard VLESS-Reality link (for Nekobox/v2rayNG)
        # Format: vless://uuid@ip:port?security=reality&sni=sni&fp=chrome&type=tcp&headerType=none#Alias
        link = f"vless://{uuid}@{ip}:{port}?security=reality&sni={sni}&fp=chrome&type=tcp&headerType=none&flow=xtls-rprx-vision#VLESS-Reality-Olympiad"
        
        self.root.clipboard_clear()
        self.root.clipboard_append(link)
        self.root.update()
        
        messagebox.showinfo("Link Generated", 
            "VLESS Link copied to clipboard!\n\n"
            "NOTE: This link is for standard clients (Nekobox, v2rayNG).\n"
            "However, this server uses a CUSTOM encryption protocol for the Olympiad.\n"
            "Standard clients will NOT connect unless the server is reverted to standard Xray-core."
        )
        self.log("Generated VLESS link (copied to clipboard)", "SYSTEM")

    def toggle_connection(self):
        if not self.connected:
            self.connect()
        else:
            self.disconnect()

    def connect(self):
        uuid = self.entry_uuid.get().strip()
        if not uuid:
            messagebox.showerror("Error", "UUID is required!")
            return
        
        server_str = self.entry_server.get().strip()
        try:
            ip, port = server_str.split(':')
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Invalid Server Address (IP:PORT)")
            return

        self.btn_connect.config(state="disabled")
        self.log(f"Initiating connection to {ip}:{port}...", "SYSTEM")
        
        # Start async connection in thread
        threading.Thread(target=self._run_async_connect, args=(ip, port, uuid), daemon=True).start()

    def _run_async_connect(self, ip, port, uuid):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._async_connect_logic(ip, port, uuid))
        # Keep loop running for background tasks
        self.loop.run_forever()

    async def _async_connect_logic(self, ip, port, uuid):
        try:
            # Connection with timeout
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=5.0
            )
            
            # 1. Crypto Handshake
            nonce = os.urandom(16)
            self.cipher = StreamCipher(uuid, nonce)
            
            self.writer.write(nonce)
            self.log(f"Sent Nonce: {nonce.hex()[:8]}...", "ENCRYPT")

            # 2. Reality Handshake
            sni = self.entry_sni.get().strip()
            payload = self._generate_reality_payload(sni)
            encrypted_payload = self.cipher.encrypt(payload)
            
            self.writer.write(encrypted_payload)
            await self.writer.drain()
            self.log("Sent Encrypted Reality Handshake", "SEND")

            # 3. Verify Connection (Wait for server to accept or close)
            # In this protocol, server doesn't send "OK" immediately, it waits for data.
            # But we can send a "Hello" packet.
            
            self._set_connected(True)
            self.log("Handshake Sent. Tunnel Active.", "SUCCESS")
            
            # Start background tasks
            self.keep_alive_task = asyncio.create_task(self._keep_alive())
            self.reader_task = asyncio.create_task(self._reader_loop())

        except asyncio.TimeoutError:
            self.log("Connection Timed Out. Check Server Firewall/Port.", "ERROR")
            self._set_connected(False)
            self.loop.stop()
        except Exception as e:
            err_msg = str(e)
            if "WinError 121" in err_msg:
                self.log("Error: Semaphore Timeout. Port likely blocked.", "ERROR")
                self.log("Hint: Run 'ufw allow 4433/tcp' on server.", "SYSTEM")
            else:
                self.log(f"Connection Failed: {err_msg}", "ERROR")
            self._set_connected(False)
            self.loop.stop()

    async def _reader_loop(self):
        try:
            while self.connected:
                data = await self.reader.read(4096)
                if not data:
                    self.log("Connection closed by server", "ERROR")
                    break
                
                decrypted = self.cipher.decrypt(data)
                
                if decrypted == b'PONG':
                    pass # Keep-alive response
                elif decrypted == b'SERVER_PING':
                    self.writer.write(self.cipher.encrypt(b'PONG'))
                    await self.writer.drain()
                else:
                    text = decrypted.decode(errors='ignore')
                    self.log(f"Server: {text}", "RECV")
        except Exception as e:
            if self.connected: # Only log if we didn't intentionally disconnect
                self.log(f"Read Error: {e}", "ERROR")
        finally:
            self._set_connected(False)
            if self.loop.is_running():
                self.loop.stop()

    def _generate_reality_payload(self, sni):
        # Mock TLS ClientHello
        base = f"GET / HTTP/1.1\r\nHost: {sni}\r\n\r\n".encode()
        # Insert Magic Header randomly
        insert_pos = random.randint(0, len(base))
        return base[:insert_pos] + VLESS_MAGIC_HEADER + base[insert_pos:] + b'\x00'*10

    def _set_connected(self, status):
        self.connected = status
        if status:
            self.root.after(0, lambda: self._update_ui_connected())
        else:
            self.root.after(0, lambda: self._update_ui_disconnected())

    def _update_ui_connected(self):
        self.status_var.set("SECURE CONNECTION")
        self.status_label.config(fg="#4caf50")
        self.btn_connect.config(text="DISCONNECT", bg="#f44336", state="normal")
        self.btn_send.config(state="normal", bg="#007acc")
        self.entry_server.config(state="disabled")
        self.entry_uuid.config(state="disabled")

    def _update_ui_disconnected(self):
        self.status_var.set("DISCONNECTED")
        self.status_label.config(fg="#f44336")
        self.btn_connect.config(text="CONNECT", bg="#007acc", state="normal")
        self.btn_send.config(state="disabled", bg="#2d2d2d")
        self.entry_server.config(state="normal")
        self.entry_uuid.config(state="normal")

    def disconnect(self):
        self.log("Disconnecting...", "SYSTEM")
        self.connected = False # This will stop loops
        
        # Stop System Proxy if active
        if self.local_proxy_server:
            self._stop_system_proxy()
            
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        # UI update happens in finally block of reader loop or immediately here
        self._set_connected(False)

    def send_message(self):
        msg = self.entry_message.get().strip()
        if not msg or not self.connected:
            return
        
        self.entry_message.delete(0, tk.END)
        self.log(f"> {msg}", "SEND")
        
        if msg.lower() == "/proxy":
            self._toggle_proxy()
        elif msg.lower() == "/global":
            self._toggle_system_proxy()
        else:
            asyncio.run_coroutine_threadsafe(self._async_send(msg), self.loop)

    def _toggle_proxy(self):
        if hasattr(self, 'proxy_task') and self.proxy_task and not self.proxy_task.done():
            self.proxy_task.cancel()
            self.log("[PROXY] Traffic simulation stopped.", "SYSTEM")
        else:
            self.proxy_task = asyncio.run_coroutine_threadsafe(self._run_proxy_simulation(), self.loop)
            self.log("[PROXY] Starting traffic simulation...", "SYSTEM")

    def _toggle_system_proxy(self):
        if self.local_proxy_server:
            self._stop_system_proxy()
        else:
            asyncio.run_coroutine_threadsafe(self._start_system_proxy(), self.loop)

    async def _start_system_proxy(self):
        try:
            self.local_proxy_server = await asyncio.start_server(
                self._handle_local_proxy_connection, '127.0.0.1', 10808
            )
            self.log("[SYSTEM PROXY] Listening on 127.0.0.1:10808", "SYSTEM")
            self.log(f"[DEBUG] Platform: {sys.platform}", "SYSTEM")
            
            # Set Windows Proxy
            if sys.platform == "win32":
                import winreg
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_ALL_ACCESS)
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:10808")
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(key)
                    self.log("[SYSTEM PROXY] Windows Proxy Settings ENABLED", "SUCCESS")
                    os.system("inetcpl.cpl ,4") # Optional: Open settings to refresh
                except Exception as e:
                    self.log(f"[!] Failed to set Windows Proxy: {e}", "ERROR")
            
            # Set Linux Proxy (GNOME)
            elif sys.platform == "linux":
                try:
                    if os.system("which gsettings > /dev/null 2>&1") == 0:
                        self.log("[DEBUG] Found gsettings, applying GNOME proxy...", "SYSTEM")
                        os.system("gsettings set org.gnome.system.proxy mode 'manual'")
                        os.system("gsettings set org.gnome.system.proxy.http host '127.0.0.1'")
                        os.system("gsettings set org.gnome.system.proxy.http port 10808")
                        os.system("gsettings set org.gnome.system.proxy.https host '127.0.0.1'")
                        os.system("gsettings set org.gnome.system.proxy.https port 10808")
                        self.log("[SYSTEM PROXY] GNOME Proxy Settings ENABLED", "SUCCESS")
                    else:
                        self.log("[!] 'gsettings' not found. Manual config required.", "ERROR")
                        self.log("    Set HTTP/HTTPS proxy to 127.0.0.1:10808", "SYSTEM")
                except Exception as e:
                    self.log(f"[!] Linux Proxy Error: {e}", "ERROR")

        except Exception as e:
            self.log(f"Failed to start local proxy: {e}", "ERROR")

    def _stop_system_proxy(self):
        if self.local_proxy_server:
            self.local_proxy_server.close()
            self.local_proxy_server = None
            
        # Disable Windows Proxy
        if sys.platform == "win32":
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_ALL_ACCESS)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                self.log("[SYSTEM PROXY] Windows Proxy Settings DISABLED", "SYSTEM")
            except Exception:
                pass
        
        # Disable Linux Proxy
        elif sys.platform == "linux":
            try:
                if os.system("which gsettings > /dev/null 2>&1") == 0:
                    os.system("gsettings set org.gnome.system.proxy mode 'none'")
                    self.log("[SYSTEM PROXY] GNOME Proxy Settings DISABLED", "SYSTEM")
            except Exception:
                pass

    async def _handle_local_proxy_connection(self, local_reader, local_writer):
        try:
            # Read request from browser/system
            data = await local_reader.read(4096)
            if not data: return
            
            # Encrypt and forward to VLESS tunnel
            # Note: In a real implementation, we need a separate VLESS stream per connection.
            # Here we are multiplexing everything into ONE tunnel, which is messy but demonstrates the concept.
            
            encrypted_req = self.cipher.encrypt(data)
            self.writer.write(encrypted_req)
            await self.writer.drain()
            
            # We can't easily route the response back to the specific local_writer 
            # because the main read_loop consumes all server responses.
            # This is the limitation of this simple single-socket tunnel.
            
            local_writer.close()
        except Exception as e:
            # self.log(f"Local Proxy Error: {e}", "ERROR")
            pass

    async def _run_proxy_simulation(self):
        urls = [
            "https://www.google.com/search?q=vless",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://api.twitter.com/1.1/statuses/update.json",
            "https://www.github.com/ospab/ospab.vpn",
            "https://aws.amazon.com/ec2/pricing"
        ]
        try:
            while self.connected:
                url = random.choice(urls)
                method = "GET" if "api" not in url else "POST"
                req = f"{method} {url} HTTP/1.1\r\nHost: {url.split('/')[2]}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                
                # Send directly via writer (thread-safe because we are in async loop)
                encrypted_req = self.cipher.encrypt(req.encode('utf-8'))
                self.writer.write(encrypted_req)
                await self.writer.drain()
                
                # Log to GUI (thread-safe call)
                self.root.after(0, lambda u=url: self.log(f"[PROXY] Tunneling: {u}", "ENCRYPT"))
                
                await asyncio.sleep(random.uniform(1.5, 4.0))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.root.after(0, lambda err=e: self.log(f"[PROXY] Error: {err}", "ERROR"))

    async def _async_send(self, msg):
        try:
            # data = f"MSG:{msg}".encode() # Old format
            data = msg.encode() # New format: Send raw command/text
            encrypted = self.cipher.encrypt(data)
            
            # Traffic Splitting
            for i in range(0, len(encrypted), CHUNK_SIZE):
                self.writer.write(encrypted[i:i+CHUNK_SIZE])
                await self.writer.drain()
                await asyncio.sleep(0.01)
            
            # Log handled in send_message for immediate feedback
            
        except Exception as e:
            self.log(f"Send Error: {e}", "ERROR")
            self._set_connected(False)

    async def _keep_alive(self):
        while self.connected:
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            try:
                self.writer.write(self.cipher.encrypt(b'PING'))
                await self.writer.drain()
            except Exception:
                break

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernVLESSClient(root)
    root.mainloop()
