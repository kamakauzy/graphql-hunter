@echo off
REM Quick start script for Windows

echo ================================
echo GraphQL Hunter - Quick Start
echo ================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo [OK] Python is installed
echo.

REM Check if dependencies are installed
echo Checking dependencies...
python -c "import requests" 2>nul
if errorlevel 1 (
    echo.
    echo [!] Dependencies not installed. Installing now...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

echo [OK] Dependencies are ready
echo.
echo ================================
echo GraphQL Hunter is ready!
echo ================================
echo.
echo Usage:
echo   python graphql-hunter.py -u https://api.example.com/graphql
echo.
echo For help:
echo   python graphql-hunter.py --help
echo.
echo Test the tool:
echo   python test_tool.py
echo.
pause

