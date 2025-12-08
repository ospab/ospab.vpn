@echo off
chcp 65001 >nul
echo ============================================
echo   UUID Generator for VLESS-Reality
echo ============================================
echo.

echo Generating new UUID...
echo.

python -c "import uuid; u = uuid.uuid4(); print('New UUID:', u); print(); print('Copy this UUID to:'); print('  1. server.py - line: VLESS_UUID = \"' + str(u) + '\"'); print('  2. client.py - line: VLESS_UUID = \"' + str(u) + '\"'); print('  3. client_gui.py - line: VLESS_UUID = \"' + str(u) + '\"')"

echo.
echo ============================================
echo IMPORTANT: UUID must be IDENTICAL on both
echo server and all clients!
echo ============================================
echo.

pause
