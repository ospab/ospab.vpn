# VLESS-Reality Configuration File
# Edit this file for production deployment

# ============================================
# SERVER CONFIGURATION
# ============================================

# Server listening address
# Use 0.0.0.0 to listen on all interfaces
# Use 127.0.0.1 for localhost only
SERVER_ADDRESS = "0.0.0.0"

# Server port
# 443 is recommended for production (looks like HTTPS)
# 4433 for testing
SERVER_PORT = 4433

# ============================================
# SECURITY CONFIGURATION
# ============================================

# UUID - CHANGE THIS FOR PRODUCTION!
# Generate new: python -c "import uuid; print(uuid.uuid4())"
VLESS_UUID = "12345678-1234-5678-1234-567812345678"

# IP Whitelist
# Empty list = allow all IPs (NOT recommended for production)
# Add allowed IPs: ["1.2.3.4", "5.6.7.8"]
ALLOWED_IPS = []

# Rate Limiting
# Maximum failed authentication attempts before ban
MAX_FAILED_ATTEMPTS = 5

# Ban duration in seconds (3600 = 1 hour)
BAN_TIME = 3600

# ============================================
# REALITY PROTOCOL
# ============================================

# Decoy SNI - domain to impersonate
# Use popular CDN or cloud provider
REALITY_SNI = "www.microsoft.com"

# Alternative SNIs (comment out above and uncomment one below):
# REALITY_SNI = "www.cloudflare.com"
# REALITY_SNI = "www.google.com"
# REALITY_SNI = "aws.amazon.com"

# ============================================
# KEEP-ALIVE SETTINGS
# ============================================

# Maximum idle time before connection closes (seconds)
KEEP_ALIVE_TIMEOUT = 300

# Interval for keep-alive PING packets (seconds)
KEEP_ALIVE_INTERVAL = 60

# ============================================
# TRAFFIC OBFUSCATION
# ============================================

# Chunk size for traffic splitting (bytes)
# Smaller = harder to detect, but more overhead
CHUNK_SIZE = 50

# Random delay range (seconds)
MIN_DELAY = 0.01
MAX_DELAY = 0.05
