@echo off
chcp 65001 >nul
echo ============================================
echo   VLESS-Reality Mock Server
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
if not exist "server.py" (
    echo [ERROR] File server.py not found!
    pause
    exit /b 1
)

echo.
echo Starting server...
echo Port: 4433
echo UUID: 12345678-1234-5678-1234-567812345678
echo Reality SNI: www.microsoft.com
echo.

python server.py
if errorlevel 1 (
    echo.
    echo [ERROR] Server launch failed
    pause
)
