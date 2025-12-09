# vless_reality_server.py

import asyncio
import uuid
import sys
import hashlib
import time
import logging

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

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("VLESS_Server")

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

def check_ip_allowed(ip: str) -> bool:
    """
    Проверка IP по whitelist и ban list.
    Возвращает True если IP разрешен.
    """
    # Проверка ban list
    if ip in banned_ips:
        # Проверяеть, не истек ли ban
        if ip in failed_attempts:
            count, ban_until = failed_attempts[ip]
            if time.time() < ban_until:
                logger.warning(f"IP {ip} is banned until {ban_until}")
                return False
            else:
                # Ban истек, убираем из banned
                banned_ips.remove(ip)
                del failed_attempts[ip]
    
    # Проверка whitelist (если указан)
    if ALLOWED_IPS and ip not in ALLOWED_IPS:
        logger.warning(f"IP {ip} not in whitelist")
        return False
    
    return True

def record_failed_attempt(ip: str):
    """Записываем неудачную попытку аутентификации"""
    if ip not in failed_attempts:
        failed_attempts[ip] = [1, 0]
    else:
        failed_attempts[ip][0] += 1
    
    count = failed_attempts[ip][0]
    
    if count >= MAX_FAILED_ATTEMPTS:
        ban_until = time.time() + BAN_TIME
        failed_attempts[ip][1] = ban_until
        banned_ips.add(ip)
        logger.error(f"IP {ip} banned for {BAN_TIME}s after {count} failed attempts")

def handle_reality_handshake(decrypted_data: bytes) -> bool:
    """
    Verifies the decrypted handshake data contains the magic header.
    """
    # 1. Check length
    if len(decrypted_data) < 10: # Minimal check
        return False
    
    # 2. Check for Magic Header
    if VLESS_MAGIC_HEADER in decrypted_data:
        return True
    else:
        return False

async def handle_client(reader, writer):
    """Handles incoming client connection."""
    addr = writer.get_extra_info('peername')
    client_ip = addr[0] if addr else 'unknown'
    
    logger.info(f"New connection from {addr}")
    
    # Security: Check IP whitelist and ban list
    if not check_ip_allowed(client_ip):
        logger.warning(f"Connection from {client_ip} rejected (whitelist/banned)")
        writer.close()
        await writer.wait_closed()
        return

    try:
        # Step 1: Read Nonce (16 bytes)
        nonce = await reader.read(16)
        if len(nonce) < 16:
            logger.warning(f"Connection from {addr} too short (no nonce)")
            writer.close()
            return

        # Initialize Cipher
        cipher = StreamCipher(VLESS_UUID, nonce)

        # Step 2: Read Encrypted Handshake
        encrypted_handshake = await reader.read(4096)
        decrypted_handshake = cipher.decrypt(encrypted_handshake)
        
        # Step 3: Reality Check
        if not handle_reality_handshake(decrypted_handshake):
            # If the check fails, we can pretend to be the Decoy server
            logger.warning(f"Traffic from {addr} is not VLESS (Handshake failed). Responding as Decoy.")
            
            # Security: Record failed attempt for rate limiting
            record_failed_attempt(client_ip)
            
            # --- Decoy Simulation ---
            writer.write(b'HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        logger.info(f"Client {addr} authenticated successfully.")
        
        # --- Start VLESS Data Tunnel (Encrypted) ---
        
        last_ping_time = asyncio.get_event_loop().time()
        
        while True:
            # Step 4: Data Tunneling (Read Encrypted VLESS data)
            try:
                encrypted_data = await asyncio.wait_for(reader.read(8192), timeout=KEEP_ALIVE_TIMEOUT)
            except asyncio.TimeoutError:
                logger.info(f"Keep-alive timeout for {addr}, closing connection")
                break
                
            if not encrypted_data:
                logger.info(f"Client {addr} closed connection")
                break
            
            # Decrypt data
            data = cipher.decrypt(encrypted_data)
            
            # Handle PING/PONG keep-alive
            if data == b'PING':
                logger.debug(f"Received PING from {addr}, sending PONG")
                writer.write(cipher.encrypt(b'PONG'))
                await writer.drain()
                last_ping_time = asyncio.get_event_loop().time()
                continue
            
            # Handle client PONG response to server PING
            if data == b'PONG':
                logger.debug(f"Received PONG from {addr}")
                last_ping_time = asyncio.get_event_loop().time()
                continue
            
            # Send PING if no activity for KEEP_ALIVE_INTERVAL
            current_time = asyncio.get_event_loop().time()
            if current_time - last_ping_time > KEEP_ALIVE_INTERVAL:
                logger.debug(f"Sending keep-alive PING to {addr}")
                writer.write(cipher.encrypt(b'SERVER_PING'))
                await writer.drain()
                last_ping_time = current_time
            
            # Decode and display message content
            decoded_data = data.decode('utf-8', errors='ignore')
            logger.info(f"Received {len(data)} bytes from {addr}")
            logger.info(f"Message content: {decoded_data}")
            
            # Step 5: Process and Forward Data (Echo for mock)
            response_text = f"[SERVER ECHO] {decoded_data}"
            encrypted_response = cipher.encrypt(response_text.encode('utf-8'))
            
            writer.write(encrypted_response)
            await writer.drain()
            logger.info(f"Sent echo response ({len(encrypted_response)} bytes)")

    except ConnectionResetError:
        logger.warning(f"Connection closed abruptly by {addr}")
    except Exception as e:
        logger.error(f"Error handling connection from {addr}: {e}")
    finally:
        logger.info(f"Connection closed for {addr}")
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
    print(f"Encryption: ChaCha20-Poly1305 (Mocked via SHA256 Stream Cipher)")
    print("="*60 + "\n")
    
    server = await asyncio.start_server(
        handle_client, '0.0.0.0', LISTEN_PORT
    )
    
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logger.info(f"Server is ready on {addrs}")
    print(f"[~] Press Ctrl+C to stop\n")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped manually.")