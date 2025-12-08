# VLESS-Reality VPN Protocol Implementation

## Architecture Overview

This is a **mock implementation** of a VLESS-Reality VPN protocol designed to demonstrate censorship circumvention techniques. The codebase consists of two async Python components:

- `client.py` - VLESS client with Reality protocol handshake and traffic obfuscation
- `server.py` - VLESS server with Reality decoy mechanism and traffic tunneling

**Key Concept**: The Reality protocol disguises VPN traffic as legitimate TLS traffic to a popular website (SNI: `www.microsoft.com`). The server acts as a decoy, responding like the real website when it detects non-VLESS traffic, but establishing a tunnel when the magic header is present.

## Critical Implementation Patterns

### Reality Handshake Flow
1. Client generates a mock TLS ClientHello packet targeting `REALITY_SNI`
2. Client embeds `VLESS_MAGIC_HEADER` (b'\x56\x4c\x45\x53') at a random position in the payload
3. Server inspects incoming data for the magic header
4. Server responds as decoy (HTTP 404) if header is missing, or proceeds with VLESS tunnel if valid

### Traffic Obfuscation Techniques
- **Fingerprint Mitigation**: `generate_fingerprinted_reality_payload()` mimics legitimate browser TLS handshakes
- **Traffic Splitting**: Client sends data in 50-byte chunks with random 0.01-0.05s delays to evade DPI (Deep Packet Inspection)
- **Random Insertion**: Magic header is randomly inserted within the payload to complicate pattern matching

### UUID Authentication
Both client and server must use matching UUIDs. **Fixed to `12345678-1234-5678-1234-567812345678`** for this demo - in production, these should be pre-shared secrets exchanged securely.

### Persistent Connection
- **Keep-Alive Mode**: Client maintains persistent connection with 300s timeout
- **PING/PONG Protocol**: Client sends PING every 60s, server responds with PONG
- **Bidirectional**: Server can also send PING, client responds with PONG
- **Interactive Mode**: After initial handshake, client can send multiple messages
- **Timeout Handling**: Connection auto-closes on timeout, logs disconnection gracefully

## Developer Workflows

### Quick Start (Recommended)

**Windows**:
```batch
start_server.bat  # Terminal 1
start_client.bat  # Terminal 2
REM or
start_client_gui.bat  # GUI version
```

**Linux** (requires root):
```bash
sudo ./start_server.sh  # Terminal 1
sudo ./start_client.sh  # Terminal 2
# or
sudo ./start_client_gui.sh  # GUI version
```

Linux scripts automatically install Python3, pip, and tkinter if missing.

### Testing

**Windows**: `test_connection.bat`  
**Linux**: `./test_connection.sh`

Tests check: Python availability, port connectivity, decoy response, file existence.

### Running Manually
```powershell
python .\server.py
```
Listens on `0.0.0.0:4433`. Prints Reality SNI and VLESS UUID on startup.

### Running the Client (Manual)
```powershell
python .\client.py
```
Connects to `127.0.0.1:4433`, sends Reality handshake, enters interactive mode for multiple messages.

### Testing the Decoy Mechanism
To verify the server responds as a decoy to non-VLESS traffic:
```powershell
curl http://127.0.0.1:4433
```
Should receive `HTTP/1.1 404 Not Found`.

## Configuration Constants

All configuration is at the top of each file:
- `SERVER_IP`/`SERVER_PORT` - Connection endpoint (default: 127.0.0.1:4433)
- `REALITY_SNI` - SNI to impersonate (must match on client/server)
- `VLESS_UUID` - Authentication token (must match on client/server)
- `VLESS_MAGIC_HEADER` - Protocol identifier (b'\x56\x4c\x45\x53')
- `CHUNK_SIZE` - Traffic splitting size (50 bytes in client)

## Code Conventions

- **Async/await**: All network operations use `asyncio`
- **Section Comments**: Major logic blocks are marked with `# --- Section Name (Category) ---`
- **Print Prefixes**: `[>]` outgoing, `[+]` success, `[-]` error, `[~]` info, `[<]` closing
- **Error Handling**: Graceful degradation with try-except-finally, always closes writers

## Key Mock Limitations

This is an **educational mock** - not production-ready:
1. TLS handshake is simplified (real implementations need full TLS 1.3 mimicry)
2. UUID is hardcoded (should be generated and exchanged securely)
3. No actual traffic forwarding (server echoes data back)
4. No encryption beyond the mock Reality layer
5. Whitelist/destination checks are placeholders

When extending this code, focus on implementing actual TLS fingerprinting libraries (e.g., uTLS for Go) and proper VLESS protocol headers according to spec.

## Documentation Files

- `README.md` - Full project overview, architecture diagrams, and setup guide
- `start_server.bat/sh` - Server launchers for Windows/Linux
- `start_client.bat/sh` - Console client launchers
- `start_client_gui.bat/sh` - GUI client launchers
- `test_connection.bat/sh` - Connection test scripts

## File Structure

- `server.py` - VLESS-Reality server with decoy mechanism and keep-alive
- `client.py` - Console VLESS client with traffic obfuscation and keep-alive
- `client_gui.py` - GUI VLESS client with tkinter interface and keep-alive

## Key Features Added

### Keep-Alive Mechanism
Both client and server implement PING/PONG keep-alive:
- **Interval**: 60 seconds between PING packets
- **Timeout**: 300 seconds maximum idle time
- **Bidirectional**: Both ends can initiate PING
- **Auto-recovery**: Connection closes gracefully on timeout

### Linux Support
Shell scripts (`.sh`) automatically:
- Check for root privileges
- Install Python3, pip, tkinter if missing
- Support apt (Debian/Ubuntu), yum (CentOS), dnf (Fedora)
- Provide same functionality as Windows batch files

### Connection Testing
Test scripts verify:
- Python and asyncio availability
- Server port accessibility
- Decoy mechanism (HTTP 404 response)
- Required files presence

## Python Environment

- Python 3.7+ required (uses `asyncio.run()`)
- No external dependencies - uses only standard library
- Windows PowerShell is the primary development environment

## Olympiad Context

This implementation is designed for **municipal stage cybersecurity olympiad**. Focus areas:
- Censorship circumvention techniques
- DPI evasion mechanisms
- Traffic obfuscation patterns
- Decoy server implementation
