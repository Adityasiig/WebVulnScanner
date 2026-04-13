@echo off
title WebVulnScanner
color 0A

echo.
echo  ============================================================
echo   WebVulnScan - Web Vulnerability Scanner v1.0
echo   Educational Use Only - Scan only authorized targets
echo  ============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo  Download Python from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM Check if dependencies are installed
python -c "import requests, bs4, colorama, jinja2" >nul 2>&1
if errorlevel 1 (
    echo  [*] Installing required dependencies...
    echo.
    pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo  [ERROR] Failed to install dependencies.
        echo  Try running: pip install -r requirements.txt manually.
        echo.
        pause
        exit /b 1
    )
    echo.
    echo  [OK] Dependencies installed successfully.
    echo.
)

REM If a URL was passed as argument, use it directly
if not "%~1"=="" (
    python scanner.py -u %*
    echo.
    pause
    exit /b 0
)

REM Interactive mode
:MENU
echo  Select scan type:
echo.
echo   [1]  Quick scan     (headers + sensitive files + ssl)
echo   [2]  Full scan      (all modules, deeper crawl)
echo   [3]  SQLi + XSS     (injection testing only)
echo   [4]  Custom scan    (choose modules manually)
echo   [5]  Exit
echo.
set /p CHOICE="  Enter choice [1-5]: "

if "%CHOICE%"=="1" goto QUICK
if "%CHOICE%"=="2" goto FULL
if "%CHOICE%"=="3" goto INJECT
if "%CHOICE%"=="4" goto CUSTOM
if "%CHOICE%"=="5" goto END
echo  [!] Invalid choice. Try again.
echo.
goto MENU

:GET_URL
echo.
set /p TARGET="  Enter target URL (e.g. https://example.com): "
if "%TARGET%"=="" (
    echo  [!] URL cannot be empty.
    goto GET_URL
)
goto %RETURN_TO%

:QUICK
set RETURN_TO=DO_QUICK
goto GET_URL
:DO_QUICK
echo.
echo  [*] Starting quick scan on %TARGET% ...
echo.
python scanner.py -u %TARGET% -m headers sensitive ssl
goto DONE

:FULL
set RETURN_TO=DO_FULL
goto GET_URL
:DO_FULL
echo.
echo  [*] Starting full scan on %TARGET% ...
echo.
python scanner.py -u %TARGET% --full
goto DONE

:INJECT
set RETURN_TO=DO_INJECT
goto GET_URL
:DO_INJECT
echo.
echo  [*] Starting injection scan on %TARGET% ...
echo.
python scanner.py -u %TARGET% -m sqli xss traversal redirect
goto DONE

:CUSTOM
echo.
echo  Available modules: sqli  xss  headers  sensitive  traversal  redirect  ssl
echo.
set /p MODULES="  Enter modules (space-separated, e.g. sqli xss headers): "
set RETURN_TO=DO_CUSTOM
goto GET_URL
:DO_CUSTOM
echo.
echo  [*] Starting custom scan on %TARGET% with modules: %MODULES%
echo.
python scanner.py -u %TARGET% -m %MODULES%
goto DONE

:DONE
echo.
echo  ============================================================
echo   Scan complete. Reports saved in the 'reports' folder.
echo  ============================================================
echo.
set /p AGAIN="  Run another scan? [Y/N]: "
if /i "%AGAIN%"=="Y" (
    echo.
    goto MENU
)

:END
echo.
echo  Goodbye!
echo.
pause
exit /b 0
