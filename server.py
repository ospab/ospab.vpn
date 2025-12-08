# vless_reality_server.py

import asyncio
import uuid
import sys

# --- Configuration (Configuration) ---
# Reality Configuration: Use a valid, unused TLS SNI/hostname (e.g., a CDN or large cloud provider)
REALITY_SNI = "www.microsoft.com"
# UUID будет сгенерирован автоматически при запуске сервера
VLESS_UUID = None
# Port to listen on - можно указать через аргумент командной строки
LISTEN_PORT = 4433
# Keep-alive settings
KEEP_ALIVE_TIMEOUT = 300  # seconds
KEEP_ALIVE_INTERVAL = 60   # seconds

# --- Security Settings (Production) ---
# IP Whitelist: Leave empty [] to allow all, or add specific IPs
# Example: ALLOWED_IPS = ['127.0.0.1', '192.168.1.100']
ALLOWED_IPS = []  # Empty = allow all (change for production!)

# Rate limiting: max failed auth attempts per IP
MAX_FAILED_ATTEMPTS = 5
BAN_TIME = 3600  # seconds (1 hour)

# Connection tracking
failed_attempts = {}  # {ip: (count, ban_until_timestamp)}
banned_ips = set() 

# --- VLESS Header Simulation (VLESS Header Structure) ---
# In a real VLESS implementation, the header includes version, UUID, and command.
# For our mock, we define a simple identifier.
VLESS_MAGIC_HEADER = b'\x56\x4c\x45\x53' # VLES (VLESS) identifier

def check_ip_allowed(ip: str) -> bool:
    """
    Проверка IP по whitelist и ban list.
    Возвращает True если IP разрешен.
    """
    import time
    
    # Проверка ban list
    if ip in banned_ips:
        # Проверяеть, не истек ли ban
        if ip in failed_attempts:
            count, ban_until = failed_attempts[ip]
            if time.time() < ban_until:
                print(f"[-] IP {ip} is banned until {ban_until}")
                return False
            else:
                # Ban истек, убираем из banned
                banned_ips.remove(ip)
                del failed_attempts[ip]
    
    # Проверка whitelist (если указан)
    if ALLOWED_IPS and ip not in ALLOWED_IPS:
        print(f"[-] IP {ip} not in whitelist")
        return False
    
    return True

def record_failed_attempt(ip: str):
    """Записываем неудачную попытку аутентификации"""
    import time
    
    if ip not in failed_attempts:
        failed_attempts[ip] = [1, 0]
    else:
        failed_attempts[ip][0] += 1
    
    count = failed_attempts[ip][0]
    
    if count >= MAX_FAILED_ATTEMPTS:
        ban_until = time.time() + BAN_TIME
        failed_attempts[ip][1] = ban_until
        banned_ips.add(ip)
        print(f"[!] IP {ip} banned for {BAN_TIME}s after {count} failed attempts")

def handle_reality_handshake(data: bytes) -> bool:
    """
    Simulates the Reality handshake verification.
    The client sends a payload disguised as a TLS ClientHello packet 
    intended for REALITY_SNI, but containing the VLESS_MAGIC_HEADER.
    """
    # 1. Check if the initial data length is reasonable for a ClientHello/Reality payload
    if len(data) < 50:
        print("[-] Handshake failed: Data too short.")
        return False
    
    # 2. Advanced Check: In a real Reality setup, the server checks the SNI 
    #    in the TLS ClientHello (Client Hello) against REALITY_SNI 
    #    and checks for a unique "Xver" field (unique ID).
    
    # For this mock, we simplify and check for our VLESS_MAGIC_HEADER 
    # embedded *within* the initial disguised packet.
    if VLESS_MAGIC_HEADER in data:
        print("[+] Reality/VLESS Handshake passed.")
        return True
    else:
        print("[-] Reality/VLESS Handshake failed: Magic header not found.")
        return False

async def handle_client(reader, writer):
    """Handles incoming client connection."""
    addr = writer.get_extra_info('peername')
    client_ip = addr[0] if addr else 'unknown'
    
    print(f"[>] New connection from {addr}")
    
    # Security: Check IP whitelist and ban list
    if not check_ip_allowed(client_ip):
        print(f"[!] Connection from {client_ip} rejected (whitelist/banned)")
        writer.close()
        await writer.wait_closed()
        return

    try:
        # Step 1: Receive the initial handshake data
        initial_data = await reader.read(4096)
        
        # Step 2: Reality Check
        if not handle_reality_handshake(initial_data):
            # If the check fails, we can pretend to be the Decoy server
            print(f"[!] Traffic from {addr} is not VLESS. Responding as Decoy.")
            
            # Security: Record failed attempt for rate limiting
            record_failed_attempt(client_ip)
            
            # --- Decoy Simulation ---
            # In a real setup, this would serve the actual website content 
            # for REALITY_SNI using the decoy's TLS certificate.
            writer.write(b'HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # Step 3: VLESS Authentication (Mock)
        # In a real VLESS, the UUID is exchanged securely. 
        # Here we assume the UUID was part of the validated handshake payload.
        # We simulate the authentication success.
        
        print(f"[+] Client {addr} authenticated successfully.")
        
        # --- Start VLESS Data Tunnel (VLESS Tunneling) ---
        
        # The VLESS server now reads the command header (e.g., connect to destination X)
        # For simplicity, we just echo data back in this mock.
        
        print(f"[+] Starting tunnel for {addr}")
        
        last_ping_time = asyncio.get_event_loop().time()
        
        while True:
            # Step 4: Data Tunneling (Read VLESS data)
            try:
                data = await asyncio.wait_for(reader.read(8192), timeout=KEEP_ALIVE_TIMEOUT)
            except asyncio.TimeoutError:
                print(f"[~] Keep-alive timeout for {addr}, closing connection")
                break
                
            if not data:
                print(f"[~] Client {addr} closed connection")
                break
            
            # Handle PING/PONG keep-alive
            if data == b'PING':
                print(f"[~] Received PING from {addr}, sending PONG")
                writer.write(b'PONG')
                await writer.drain()
                last_ping_time = asyncio.get_event_loop().time()
                continue
            
            # Handle client PONG response to server PING
            if data == b'PONG':
                print(f"[~] Received PONG from {addr}")
                last_ping_time = asyncio.get_event_loop().time()
                continue
            
            # Send PING if no activity for KEEP_ALIVE_INTERVAL
            current_time = asyncio.get_event_loop().time()
            if current_time - last_ping_time > KEEP_ALIVE_INTERVAL:
                print(f"[~] Sending keep-alive PING to {addr}")
                writer.write(b'SERVER_PING')
                await writer.drain()
                last_ping_time = current_time
            
            # --- VLESS Enhancement: White List Check (Mock) ---
            # Assume data contains the destination IP/Port that needs verification
            # In a real scenario, this check happens after the VLESS command is parsed.
            
            # Decode and display message content
            decoded_data = data.decode('utf-8', errors='ignore')
            print(f"\n[~] Received {len(data)} bytes from {addr}")
            print(f"[<] Message content: {decoded_data}")
            
            # Step 5: Process and Forward Data (Echo for mock)
            response = f"[SERVER ECHO] {decoded_data}".encode('utf-8')
            writer.write(response)
            await writer.drain()
            print(f"[>] Sent echo response ({len(response)} bytes)\n")

    except ConnectionResetError:
        print(f"[-] Connection closed abruptly by {addr}")
    except Exception as e:
        print(f"[-] Error handling connection from {addr}: {e}")
    finally:
        print(f"[<] Connection closed for {addr}")
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()

async def main():
    """Starts the VLESS-Reality Mock Server."""
    global VLESS_UUID, LISTEN_PORT
    
    # Генерация нового UUID при каждом запуске
    VLESS_UUID = str(uuid.uuid4())
    
    # Проверка аргументов командной строки для порта
    if len(sys.argv) > 1:
        try:
            LISTEN_PORT = int(sys.argv[1])
        except ValueError:
            print(f"[-] Invalid port number: {sys.argv[1]}. Using default {LISTEN_PORT}")
    
    print("="*60)
    print("--- VLESS-Reality Mock Server Starting ---")
    print("="*60)
    print(f"\n[!] COPY THIS UUID TO YOUR CLIENT:")
    print(f"\n    {VLESS_UUID}\n")
    print(f"Reality Decoy SNI: {REALITY_SNI}")
    print(f"Listening Port: {LISTEN_PORT}")
    print("="*60 + "\n")
    
    server = await asyncio.start_server(
        handle_client, '0.0.0.0', LISTEN_PORT
    )
    
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[+] Server is ready on {addrs}")
    print(f"[~] Press Ctrl+C to stop\n")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped manually.")