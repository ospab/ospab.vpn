# VLESS-Reality VPN

Encrypted VPN tunnel with traffic obfuscation.

## Quick Start

### Server
```bash
# Windows
python server.py [port] [uuid]

# Linux
python3 server.py [port] [uuid]
```

Server will display UUID on startup if not provided.

### Client
```bash
# Windows
python client.py <uuid> [server_ip] [port]

# Linux
python3 client.py <uuid> [server_ip] [port]
```

Client starts HTTP proxy on `127.0.0.1:10808` and configures system proxy automatically.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UUID` | auto-generated | Authentication key |
| `PORT` | 4433 | Server listen port |
| `SERVER` | 127.0.0.1 | Server IP (client) |
| `SNI` | www.microsoft.com | TLS SNI for camouflage |

## How It Works

1. Client connects to server with encrypted Reality handshake
2. Server validates magic header, rejects invalid traffic as HTTP 404 (decoy)
3. Client starts local HTTP proxy (10808)
4. All HTTP/HTTPS traffic is tunneled through encrypted connection
5. Server forwards requests to target and returns responses

## Security Features

- SHA256-based stream cipher encryption
- IP ban after 5 failed auth attempts (1 hour)
- Decoy response for non-VLESS traffic (mimics nginx 404)
- Traffic obfuscation via Reality protocol

## Files

- `server.py` - VPN server with proxy relay
- `client.py` - VPN client with local HTTP proxy
- `start_server.bat/sh` - Server launcher
- `start_client.bat/sh` - Client launcher

## Requirements

- Python 3.7+
- No external dependencies
