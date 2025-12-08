@echo off
chcp 65001 >nul
echo ============================================
echo   VLESS-Reality Connection Test
echo ============================================
echo.

set SERVER=127.0.0.1
set PORT=4433

REM Allow custom server for remote testing
if not "%1"=="" set SERVER=%1

echo Testing connection to %SERVER%:%PORT%...
echo.

REM Test 1: Python availability
echo [1/5] Python environment test...
python --version >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Python not found
    goto :error
)
python --version
echo [PASS] Python found
echo.

REM Test 2: Python asyncio
echo [2/5] Checking asyncio module...
python -c "import asyncio" 2>nul
if errorlevel 1 (
    echo [FAIL] asyncio not available - Python version too old?
    goto :error
)
echo [PASS] asyncio available
echo.

REM Test 3: Files existence
echo [3/5] Project files test...
if not exist "server.py" (
    echo [FAIL] server.py not found
    goto :error
)
if not exist "client.py" (
    echo [FAIL] client.py not found
    goto :error
)
echo [PASS] All required files present
echo.

REM Test 4: Port check with netstat
echo [4/5] Checking if port %PORT% is in use...
netstat -an | findstr ":%PORT%" | findstr "LISTENING" >nul
if errorlevel 1 (
    echo [WARN] Port %PORT% not listening - server not running
    echo       Start server first: start_server.bat
) else (
    echo [PASS] Port %PORT% is listening
)
echo.

REM Test 5: Decoy response (only if server is running)
echo [5/5] Server connectivity and decoy test...
where curl >nul 2>&1
if errorlevel 1 (
    echo [SKIP] curl not available - cannot test decoy response
    echo       Install curl or test manually
) else (
    echo Testing decoy response from %SERVER%:%PORT%...
    curl -s -m 3 http://%SERVER%:%PORT% 2>nul | findstr "404" >nul
    if errorlevel 1 (
        echo [WARN] No HTTP 404 received - server might not be running
        echo       or not responding as expected
    ) else (
        echo [PASS] Decoy response received (HTTP 404)
    )
)
echo.

echo ============================================
echo Test Summary
echo ============================================
echo Server: %SERVER%:%PORT%
echo Python: OK
echo Files:  OK
echo Status: Check warnings above
echo.
echo System ready for demonstration.
echo.
echo To test remote server:
echo   test_connection.bat YOUR_SERVER_IP
echo.
pause
exit /b 0

:error
echo.
echo [ERROR] Tests failed. Fix issues above.
pause
exit /b 1
