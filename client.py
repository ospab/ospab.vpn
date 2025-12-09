#!/usr/bin/env python3
# vless_reality_client.py

import asyncio
import random
import sys
import hashlib
import logging
import os

# --- Configuration (Configuration) ---
SERVER_IP = '127.0.0.1' # Change to your server IP
SERVER_PORT = 4433
REALITY_SNI = "www.microsoft.com"
# UUID нужно скопировать с сервера или указать через аргумент командной строки
VLESS_UUID = None
VLESS_MAGIC_HEADER = b'\x56\x4c\x45\x53'
# Keep-alive settings
KEEP_ALIVE_INTERVAL = 60  # seconds 

# --- Interactive Setup ---
def configure_client():
    global SERVER_IP, SERVER_PORT, REALITY_SNI, VLESS_UUID
    
    print("\n--- Client Configuration ---")
    
    # Server IP
    ip_in = input(f"Server IP [{SERVER_IP}]: ").strip()
    if ip_in:
        SERVER_IP = ip_in
        
    # Server Port
    p_in = input(f"Server Port [{SERVER_PORT}]: ").strip()
    if p_in.isdigit():
        SERVER_PORT = int(p_in)
        
    # UUID
    if len(sys.argv) > 1:
        VLESS_UUID = sys.argv[1]
    
    if not VLESS_UUID:
        u_in = input("VLESS UUID (Required): ").strip()
        if u_in:
            VLESS_UUID = u_in
        else:
            print("[!] Error: UUID is required!")
            sys.exit(1)
            
    # SNI
    s_in = input(f"Reality SNI [{REALITY_SNI}]: ").strip()
    if s_in:
        REALITY_SNI = s_in
        
    print("\n[~] Configuration applied.")

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("VLESS_Client")

# --- Crypto (Stream Cipher) ---
class StreamCipher:
    """
    Simple Hash-based Stream Cipher (XOR) using SHA256.
    Provides confidentiality and high entropy for traffic.
    """
    def __init__(self, key: str, nonce: bytes):
        self.key = key.encode()
        self.nonce = nonce
        self.counter = 0
        self.buffer = b''

    def _refill_buffer(self):
        # Generate next block of keystream: SHA256(key + nonce + counter)
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
        return self.encrypt(data) # XOR is symmetric

# --- Client Fingerprint Mitigation (Mock Implementation) ---
# To avoid being fingerprinted (e.g., by JA3/TLS fingerprinting tools), 
# the client must mimic a popular, allowed client (browser/OS).
# We simulate a "ClientHello" that mimics an older Chrome/Safari version.

def generate_fingerprinted_reality_payload(sni: str) -> bytes:
    """
    Mocks a TLS ClientHello packet disguised for Reality SNI, 
    but embeds the VLESS header for server recognition.
    """
    
    # 1. Mock TLS Header and ClientHello structure (Simplified)
    tls_header = b'\x16\x03\x01\x00\xfa' # Example TLS Handshake header
    client_hello_part = f"GET / HTTP/1.1\r\nHost: {sni}\r\n\r\n".encode('utf-8')
    
    # 2. Embed VLESS Magic Header
    insertion_point = random.randint(10, len(client_hello_part) - 5)
    
    reality_payload = (
        tls_header + 
        client_hello_part[:insertion_point] + 
        VLESS_MAGIC_HEADER + 
        client_hello_part[insertion_point:] +
        b'padding_to_match_target_size' 
    )
    
    logger.info(f"Generated Reality payload (size: {len(reality_payload)})")
    return reality_payload

async def send_vless_data(message: str, keep_alive: bool = False):
    """Establishes connection and sends data via the mocked VLESS tunnel."""
    
    logger.info(f"Connecting to VLESS server at {SERVER_IP}:{SERVER_PORT}...")
    try:
        reader, writer = await asyncio.open_connection(SERVER_IP, SERVER_PORT)
        
        # Step 0: Generate Nonce and Initialize Cipher
        nonce = os.urandom(16)
        cipher = StreamCipher(VLESS_UUID, nonce)
        
        # Step 1: Send Nonce (Plaintext)
        writer.write(nonce)
        
        # Step 2: Reality Handshake (Encrypted)
        reality_payload = generate_fingerprinted_reality_payload(REALITY_SNI)
        encrypted_payload = cipher.encrypt(reality_payload)
        
        logger.info("Sending Encrypted Reality payload...")
        writer.write(encrypted_payload)
        await writer.drain()
        
        # Step 3: Send actual VLESS data (Encrypted)
        # vless_data = f"VLESS_COMMAND_CONNECT_TO_DEST: {message}".encode('utf-8')
        # encrypted_vless_data = cipher.encrypt(vless_data)
        
        # --- VLESS Enhancement: Traffic Splitting for DPI Evasion ---
        CHUNK_SIZE = 50 
        
        # logger.info(f"Sending Encrypted VLESS data in chunks (Size: {len(encrypted_vless_data)})")
        
        # for i in range(0, len(encrypted_vless_data), CHUNK_SIZE):
        #     chunk = encrypted_vless_data[i:i + CHUNK_SIZE]
        #     writer.write(chunk)
        #     await writer.drain()
        #     await asyncio.sleep(random.uniform(0.01, 0.05)) 

        # Step 4: Read response from the server (Encrypted)
        # encrypted_response = await asyncio.wait_for(reader.read(4096), timeout=10.0)
        
        # if encrypted_response:
        #     response = cipher.decrypt(encrypted_response)
        #     logger.info(f"Server Response Received:\n{response.decode('utf-8', errors='ignore')}")
        # else:
        #     logger.warning("No response received (Server might have acted as Decoy or closed connection).")
        
        # Step 5: Keep connection alive if requested
        if keep_alive:
            logger.info("Maintaining persistent connection...")
            
            # Background Keep-Alive Task
            async def send_keep_alive():
                while True:
                    await asyncio.sleep(KEEP_ALIVE_INTERVAL)
                    try:
                        # logger.debug("Sending keep-alive PING...")
                        writer.write(cipher.encrypt(b'PING'))
                        await writer.drain()
                    except Exception:
                        break
            
            keep_alive_task = asyncio.create_task(send_keep_alive())
            
            # Background Read Task
            async def read_loop():
                try:
                    while True:
                        encrypted_response = await reader.read(4096)
                        if not encrypted_response:
                            print("\n[!] Server closed connection.")
                            # Stop the main loop? 
                            # We can't easily stop the input() blocking call from here.
                            # But we can exit the process or set a flag.
                            os._exit(0) 
                            break
                        
                        response = cipher.decrypt(encrypted_response)
                        
                        if response == b'PONG':
                            continue
                        if response == b'SERVER_PING':
                            writer.write(cipher.encrypt(b'PONG'))
                            await writer.drain()
                            continue
                            
                        print(f"\nServer: {response.decode('utf-8', errors='ignore')}")
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    print(f"\n[!] Read error: {e}")
                    os._exit(1)

            read_task = asyncio.create_task(read_loop())
            
            # Proxy Simulation Task
            proxy_task = None
            
            async def run_proxy_simulation():
                print("\n[PROXY] Starting traffic simulation...")
                urls = [
                    "https://www.google.com/search?q=vless",
                    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                    "https://api.twitter.com/1.1/statuses/update.json",
                    "https://www.github.com/ospab/vpn",
                    "https://aws.amazon.com/ec2/pricing"
                ]
                try:
                    while True:
                        url = random.choice(urls)
                        method = "GET" if "api" not in url else "POST"
                        req = f"{method} {url} HTTP/1.1\r\nHost: {url.split('/')[2]}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                        
                        print(f"[PROXY] Tunneling: {method} {url}")
                        encrypted_req = cipher.encrypt(req.encode('utf-8'))
                        writer.write(encrypted_req)
                        await writer.drain()
                        
                        await asyncio.sleep(random.uniform(1.5, 4.0))
                except asyncio.CancelledError:
                    print("\n[PROXY] Traffic simulation stopped.")

            # --- Local Proxy Listener (Real Traffic) ---
            async def handle_local_proxy(local_reader, local_writer):
                try:
                    # Read request from browser/system
                    data = await local_reader.read(4096)
                    if not data: return
                    
                    # Encrypt and forward to VLESS tunnel
                    # Note: In a real implementation, we need a separate VLESS stream per connection.
                    # Here we are multiplexing everything into ONE tunnel, which is messy but demonstrates the concept.
                    # The server will see mixed packets if multiple requests happen.
                    # For this mock, we assume sequential requests or just fire-and-forget.
                    
                    encrypted_req = cipher.encrypt(data)
                    writer.write(encrypted_req)
                    await writer.drain()
                    
                    # We can't easily route the response back to the specific local_writer 
                    # because the main read_loop consumes all server responses.
                    # This is the limitation of this simple single-socket tunnel.
                    # But the server WILL execute the request.
                    
                    local_writer.close()
                except Exception as e:
                    print(f"Local Proxy Error: {e}")

            local_proxy_server = None

            async def start_local_proxy():
                nonlocal local_proxy_server
                try:
                    local_proxy_server = await asyncio.start_server(handle_local_proxy, '127.0.0.1', 10808)
                    print(f"\n[SYSTEM PROXY] Listening on 127.0.0.1:10808")
                except Exception as e:
                    print(f"[!] Failed to bind port 10808: {e}")
                    return

                print(f"[DEBUG] Platform detected: {sys.platform}")
                
                # Set Windows Proxy
                if sys.platform == "win32":
                    import winreg
                    try:
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_ALL_ACCESS)
                        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:10808")
                        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                        winreg.CloseKey(key)
                        print("[SYSTEM PROXY] Windows Proxy Settings ENABLED")
                        os.system("inetcpl.cpl ,4") # Optional: Open settings to refresh
                    except Exception as e:
                        print(f"[!] Failed to set Windows Proxy: {e}")
                
                # Set Linux Proxy (GNOME)
                elif sys.platform == "linux":
                    try:
                        # Check if gsettings is available
                        if os.system("which gsettings > /dev/null 2>&1") == 0:
                            print("[DEBUG] 'gsettings' found. Attempting to set GNOME proxy...")
                            os.system("gsettings set org.gnome.system.proxy mode 'manual'")
                            os.system("gsettings set org.gnome.system.proxy.http host '127.0.0.1'")
                            os.system("gsettings set org.gnome.system.proxy.http port 10808")
                            os.system("gsettings set org.gnome.system.proxy.https host '127.0.0.1'")
                            os.system("gsettings set org.gnome.system.proxy.https port 10808")
                            print("[SYSTEM PROXY] GNOME Proxy Settings ENABLED")
                        else:
                            print("[!] 'gsettings' not found. Cannot set system proxy automatically.")
                            print("    Please manually set HTTP/HTTPS proxy to 127.0.0.1:10808")
                    except Exception as e:
                        print(f"[!] Failed to set Linux Proxy: {e}")

            def stop_local_proxy():
                if local_proxy_server:
                    local_proxy_server.close()
                
                print(f"[DEBUG] Disabling proxy for platform: {sys.platform}")

                # Disable Windows Proxy
                if sys.platform == "win32":
                    import winreg
                    try:
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_ALL_ACCESS)
                        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                        winreg.CloseKey(key)
                        print("[SYSTEM PROXY] Windows Proxy Settings DISABLED")
                    except Exception:
                        pass
                
                # Disable Linux Proxy (GNOME)
                elif sys.platform == "linux":
                    try:
                        if os.system("which gsettings > /dev/null 2>&1") == 0:
                            os.system("gsettings set org.gnome.system.proxy mode 'none'")
                            print("[SYSTEM PROXY] GNOME Proxy Settings DISABLED")
                    except Exception:
                        pass

            print("\n" + "="*60)
            print("[~] Connection established!")
            print("[~] Type '/help', '/proxy' (sim), '/global' (system proxy), 'exit'")
            print("="*60)
            
            # Interactive Loop
            while True:
                try:
                    # Use run_in_executor to avoid blocking asyncio loop with input()
                    user_input = await asyncio.get_event_loop().run_in_executor(None, input, "> ")
                    user_input = user_input.strip()
                    
                    if not user_input:
                        continue
                        
                    if user_input.lower() == 'exit':
                        stop_local_proxy()
                        if proxy_task: proxy_task.cancel()
                        keep_alive_task.cancel()
                        read_task.cancel()
                        break
                    
                    if user_input.lower() == '/proxy':
                        if proxy_task and not proxy_task.done():
                            proxy_task.cancel()
                            proxy_task = None
                        else:
                            proxy_task = asyncio.create_task(run_proxy_simulation())
                        continue

                    if user_input.lower() == '/global':
                        if local_proxy_server:
                            stop_local_proxy()
                            local_proxy_server = None
                        else:
                            await start_local_proxy()
                        continue

                    # Encrypt and Send
                    encrypted_msg = cipher.encrypt(user_input.encode('utf-8'))
                    writer.write(encrypted_msg)
                    await writer.drain()
                    
                    # Response is handled by read_loop
                        
                except asyncio.TimeoutError:
                    print("[-] Timeout waiting for response")
                except Exception as e:
                    print(f"[-] Error: {e}")
                    break

    except ConnectionRefusedError:
        logger.error(f"Connection refused. Is the server running on {SERVER_IP}:{SERVER_PORT}?")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        if 'writer' in locals() and not writer.is_closing():
            writer.close()
            await writer.wait_closed()
        logger.info("VLESS Client connection closed.")


async def main():
    configure_client()
    
    print("="*60)
    print("=== VLESS-Reality Client ===")
    print(f"Target: {SERVER_IP}:{SERVER_PORT}")
    print(f"SNI:    {REALITY_SNI}")
    print("="*60)
    
    await send_vless_data("Initial Handshake", keep_alive=True)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Client stopped manually.")