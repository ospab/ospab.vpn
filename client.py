# vless_reality_client.py

import asyncio
import random
import sys

# --- Configuration (Configuration) ---
SERVER_IP = '127.0.0.1' # Change to your server IP
SERVER_PORT = 4433
REALITY_SNI = "www.microsoft.com"
# UUID нужно скопировать с сервера или указать через аргумент командной строки
VLESS_UUID = None
VLESS_MAGIC_HEADER = b'\x56\x4c\x45\x53'
# Keep-alive settings
KEEP_ALIVE_INTERVAL = 60  # seconds 

# --- Client Fingerprint Mitigation (Mock Implementation) ---
# To avoid being fingerprinted (e.g., by JA3/TLS fingerprinting tools), 
# the client must mimic a popular, allowed client (browser/OS).
# We simulate a "ClientHello" that mimics an older Chrome/Safari version.

def generate_fingerprinted_reality_payload(sni: str) -> bytes:
    """
    Mocks a TLS ClientHello packet disguised for Reality SNI, 
    but embeds the VLESS header for server recognition.
    
    In a real implementation, this payload is complex (TLS version, 
    ciphersuites, extensions, etc.) to match a specific popular fingerprint.
    """
    
    # 1. Mock TLS Header and ClientHello structure (Simplified)
    # The payload MUST look like a legitimate ClientHello destined for 'sni'
    tls_header = b'\x16\x03\x01\x00\xfa' # Example TLS Handshake header
    client_hello_part = f"GET / HTTP/1.1\r\nHost: {sni}\r\n\r\n".encode('utf-8')
    
    # 2. Embed VLESS Magic Header (The secret knockout)
    # The server uses the location/content of this magic header for its check.
    # In reality, this is often done by carefully encoding the VLESS UUID 
    # and auxiliary data into one of the TLS extensions (e.g., PskIdentity, Xver).
    
    # We embed it randomly within the payload to increase complexity for DPI
    insertion_point = random.randint(10, len(client_hello_part) - 5)
    
    reality_payload = (
        tls_header + 
        client_hello_part[:insertion_point] + 
        VLESS_MAGIC_HEADER + 
        client_hello_part[insertion_point:] +
        b'padding_to_match_target_size' # Add padding to match expected TLS packet size
    )
    
    print(f"[~] Generated Reality payload (size: {len(reality_payload)})")
    return reality_payload

async def send_vless_data(message: str, keep_alive: bool = False):
    """Establishes connection and sends data via the mocked VLESS tunnel."""
    
    print(f"[>] Connecting to VLESS server at {SERVER_IP}:{SERVER_PORT}...")
    try:
        reader, writer = await asyncio.open_connection(SERVER_IP, SERVER_PORT)
        
        # Step 1: Reality Handshake
        reality_payload = generate_fingerprinted_reality_payload(REALITY_SNI)
        print("[>] Sending Reality payload...")
        writer.write(reality_payload)
        await writer.drain()
        
        # Assuming the server accepted the handshake (no immediate close/decoy response)
        
        # Step 2: Send actual VLESS data (Mock)
        vless_data = f"VLESS_COMMAND_CONNECT_TO_DEST: {message}".encode('utf-8')
        
        # --- VLESS Enhancement: Traffic Splitting for DPI Evasion ---
        # Splitting the traffic into smaller chunks can evade DPI 
        # that looks for large packets after the handshake.
        CHUNK_SIZE = 50 
        
        print(f"[>] Sending VLESS data in chunks (Size: {len(vless_data)})")
        
        for i in range(0, len(vless_data), CHUNK_SIZE):
            chunk = vless_data[i:i + CHUNK_SIZE]
            writer.write(chunk)
            await writer.drain()
            # Introduce slight, random delay to mimic human/browser traffic
            await asyncio.sleep(random.uniform(0.01, 0.05)) 

        # Step 3: Read response from the server (Echo for mock)
        response = await asyncio.wait_for(reader.read(4096), timeout=10.0)
        
        if response:
            print(f"[+] Server Response Received:\n{response.decode('utf-8', errors='ignore')}")
        else:
            print("[-] No response received (Server might have acted as Decoy or closed connection).")
        
        # Step 4: Keep connection alive if requested
        if keep_alive:
            print("[~] Maintaining persistent connection with keep-alive...")
            
            async def send_keep_alive():
                """Периодически отправлять PING для поддержания соединения"""
                while True:
                    await asyncio.sleep(KEEP_ALIVE_INTERVAL)
                    try:
                        print("[~] Sending keep-alive PING...")
                        writer.write(b'PING')
                        await writer.drain()
                        
                        # Ожидаем PONG
                        pong = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                        if pong == b'PONG':
                            print("[+] Keep-alive PONG received")
                        elif pong == b'SERVER_PING':
                            print("[~] Server PING received, sending PONG")
                            writer.write(b'PONG')
                            await writer.drain()
                    except asyncio.TimeoutError:
                        print("[-] Keep-alive timeout")
                        break
                    except Exception as e:
                        print(f"[-] Keep-alive error: {e}")
                        break
            
            # Запускаем keep-alive в фоне
            keep_alive_task = asyncio.create_task(send_keep_alive())
            
            print("\n" + "="*60)
            print("[~] Connection established! You can now send messages.")
            print("[~] Type 'test' for a quick connection test")
            print("[~] Type 'exit' to quit")
            print("="*60)
            
            while True:
                try:
                    user_input = input("\n[Message] > ")
                    if user_input.lower() == 'exit':
                        keep_alive_task.cancel()
                        break
                    
                    if not user_input.strip():
                        continue
                    
                    # Quick test command
                    if user_input.lower() == 'test':
                        user_input = f"Connection test at {asyncio.get_event_loop().time()}"
                    
                    # Send additional messages
                    additional_data = f"USER_MESSAGE: {user_input}".encode('utf-8')
                    for i in range(0, len(additional_data), CHUNK_SIZE):
                        chunk = additional_data[i:i + CHUNK_SIZE]
                        writer.write(chunk)
                        await writer.drain()
                        await asyncio.sleep(random.uniform(0.01, 0.05))
                    
                    # Read response
                    response = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                    if response:
                        print(f"[+] Response: {response.decode('utf-8', errors='ignore')}")
                    else:
                        print("[-] Connection lost")
                        break
                        
                except asyncio.TimeoutError:
                    print("[-] Response timeout")
                    break
                except EOFError:
                    print("\n[!] Input interrupted")
                    break

    except ConnectionRefusedError:
        print(f"[!] Connection refused. Is the server running on {SERVER_IP}:{SERVER_PORT}?")
    except Exception as e:
        print(f"[-] An error occurred: {e}")
    finally:
        if 'writer' in locals() and not writer.is_closing():
            writer.close()
            await writer.wait_closed()
        print("[<] VLESS Client connection closed.")


async def main():
    global VLESS_UUID, SERVER_IP, SERVER_PORT
    
    print("="*60)
    print("=== VLESS-Reality Client ===")
    print("="*60)
    
    # Проверка аргументов командной строки
    if len(sys.argv) > 1:
        VLESS_UUID = sys.argv[1]
    
    if not VLESS_UUID:
        print("\n[!] Please provide UUID from server:")
        print("[~] (Copy from server console output)")
        VLESS_UUID = input("UUID: ").strip()
        
        if not VLESS_UUID:
            print("[-] UUID is required. Exiting.")
            return
    
    # Опционально можно указать сервер и порт
    if len(sys.argv) > 2:
        SERVER_IP = sys.argv[2]
    if len(sys.argv) > 3:
        try:
            SERVER_PORT = int(sys.argv[3])
        except ValueError:
            print(f"[-] Invalid port: {sys.argv[3]}. Using default {SERVER_PORT}")
    
    print(f"\n[~] UUID: {VLESS_UUID}")
    print(f"[~] Target: {SERVER_IP}:{SERVER_PORT}")
    print(f"[~] Reality SNI: {REALITY_SNI}\n")
    
    message_to_send = "Hello VLESS Server, I am requesting access to the covert channel."
    
    # Для демонстрации на олимпиаде - включаем keep-alive
    await send_vless_data(message_to_send, keep_alive=True)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClient stopped manually.")