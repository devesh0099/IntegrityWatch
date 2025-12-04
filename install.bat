@echo off
setlocal enabledelayedexpansion

echo IntegrityWatch Setup
echo.

REM Find Python
set PYTHON_CMD=
for %%P in (python python3 py) do (
    %%P --version >nul 2>&1
    if !errorlevel! EQU 0 (
        for /f "tokens=2" %%V in ('%%P --version 2^>^&1') do (
            set PYTHON_VERSION=%%V
            set PYTHON_CMD=%%P
            goto found
        )
    )
)

:found
if "!PYTHON_CMD!"=="" (
    echo Error: Python not found
    echo Install from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Found Python !PYTHON_VERSION!

REM Check version (3.11, 3.12, or 3.13 only)
for /f "tokens=1,2 delims=." %%A in ("!PYTHON_VERSION!") do (
    set MAJOR=%%A
    set MINOR=%%B
)

if !MAJOR! NEQ 3 goto bad_version
if !MINOR! EQU 11 goto version_ok
if !MINOR! EQU 12 goto version_ok
if !MINOR! EQU 13 goto version_ok
goto bad_version

:bad_version
echo Error: Python 3.11, 3.12, or 3.13 required
echo Found: Python !PYTHON_VERSION!
pause
exit /b 1

:version_ok

REM Create venv
if exist .venv\ (
    echo Using existing virtual environment
) else (
    echo Creating virtual environment...
    !PYTHON_CMD! -m venv .venv
    if !errorlevel! NEQ 0 (
        echo Failed to create venv
        pause
        exit /b 1
    )
)

REM Activate
call .venv\Scripts\activate.bat

REM Install
echo Installing dependencies...
python -m pip install --upgrade pip wheel >nul 2>&1

if exist wheels\ (
    echo Installing from wheels...
    pip install --no-index --find-links=wheels cpuid-native cpuid >nul 2>&1
)

pip install -e .
if !errorlevel! NEQ 0 (
    echo.
    echo Installation failed
    echo If you see C++ compiler errors, download Visual Studio Build Tools:
    echo https://visualstudio.microsoft.com/visual-cpp-build-tools/
    pause
    exit /b 1
)

echo.
echo Done! Next steps:
echo   1. Run as admin: python -m src.browser_monitor.core.install
echo   2. Start: python -m src.main
echo.
pause
