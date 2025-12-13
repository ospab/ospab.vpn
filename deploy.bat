@echo off
chcp 65001 >nul
title ospab.vpn Deploy

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║           ospab.vpn Deployment Script            ║
echo ╠══════════════════════════════════════════════════╣
echo ║  • Check Python installation                     ║
echo ║  • Generate configuration                        ║
echo ║  • Create config.yml                             ║
echo ╚══════════════════════════════════════════════════╝
echo.

:: Check Python
echo [1/3] Checking dependencies...
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] Python not found!
    echo [!] Please install Python 3.8+ from python.org
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo [+] %%i found

:: Configuration
echo.
echo [2/3] Server Configuration
echo ────────────────────────────────────────

set /p PORT="[?] Server port [443]: "
if "%PORT%"=="" set PORT=443

set /p UUID="[?] UUID (empty=generate): "
if "%UUID%"=="" (
    for /f %%i in ('python -c "import uuid; print(uuid.uuid4())"') do set UUID=%%i
    echo [+] Generated UUID: %UUID%
)

set /p SNI="[?] SNI domain [www.microsoft.com]: "
if "%SNI%"=="" set SNI=www.microsoft.com

:: Create config.yml
echo.
echo [3/3] Creating Configuration Files
echo ────────────────────────────────────────

(
echo # ospab.vpn server configuration
echo # Generated: %date% %time%
echo.
echo server:
echo   port: %PORT%
echo   uuid: "%UUID%"
echo   sni: "%SNI%"
echo.
echo proxy:
echo   port: 10808
) > config.yml

echo [+] Created config.yml

:: Create run scripts
(
echo @echo off
echo chcp 65001 ^>nul
echo title ospab.vpn Server
echo cd /d "%%~dp0"
echo python server.py
echo pause
) > run_server.bat

echo [+] Created run_server.bat

(
echo @echo off
echo chcp 65001 ^>nul
echo title ospab.vpn Client
echo cd /d "%%~dp0"
echo python client.py
echo pause
) > run_client.bat

echo [+] Created run_client.bat

:: Get local IP
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
    for /f "tokens=1" %%b in ("%%a") do set LOCAL_IP=%%b
    goto :got_ip
)
:got_ip

:: Summary
echo.
echo ╔══════════════════════════════════════════════════╗
echo ║           Deployment Complete!                   ║
echo ╠══════════════════════════════════════════════════╣
echo ║  IP:     %LOCAL_IP%
echo ║  Port:   %PORT%
echo ║  UUID:   %UUID%
echo ║  SNI:    %SNI%
echo ╠══════════════════════════════════════════════════╣
echo ║  To start server: run_server.bat                 ║
echo ║  To start client: run_client.bat                 ║
echo ║  Or just: python server.py / python client.py    ║
echo ╚══════════════════════════════════════════════════╝
echo.

set /p START="[?] Start server now? [Y/n]: "
if /i "%START%"=="" set START=Y
if /i "%START%"=="Y" (
    echo.
    echo [*] Starting server...
    python server.py
)

pause
