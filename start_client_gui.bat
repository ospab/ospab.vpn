@echo off
chcp 65001 >nul
echo ============================================
echo   VLESS-Reality Client (GUI)
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

REM Check tkinter
echo Checking tkinter...
python -c "import tkinter; print('[OK] tkinter available')" 2>nul
if errorlevel 1 (
    echo [ERROR] tkinter not found! Reinstall Python with Tcl/Tk support
    pause
    exit /b 1
)

REM Check file exists
if not exist "client_gui.py" (
    echo [ERROR] File client_gui.py not found!
    pause
    exit /b 1
)

echo.
echo Launching GUI client...
echo Server: 127.0.0.1:4433
echo UUID: 12345678-1234-5678-1234-567812345678
echo Reality SNI: www.microsoft.com
echo.

start pythonw client_gui.py
if errorlevel 1 (
    echo.
    echo [ERROR] GUI client launch failed
    pause
)
