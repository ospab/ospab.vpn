@echo off
chcp 65001 >nul
echo ============================================
echo   VLESS-Reality Client (Console)
echo   Municipal Stage Cybersecurity Olympiad
echo ============================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Install Python 3.7+
    pause
    exit /b 1
)

echo [OK] Python found
python --version

REM Check file exists
if not exist "client.py" (
    echo [ERROR] File client.py not found!
    pause
    exit /b 1
)

echo.
echo Connecting to server...
echo Server: 127.0.0.1:4433
echo UUID: 12345678-1234-5678-1234-567812345678
echo Reality SNI: www.microsoft.com
echo.

python client.py
if errorlevel 1 (
    echo.
    echo [ERROR] Client launch failed
    pause
)
