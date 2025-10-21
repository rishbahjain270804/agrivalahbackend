@echo off
cd /d "%~dp0"
echo ====================================
echo Natural Farming Registration System
echo Node.js Server Startup
echo ====================================

echo.
echo Checking for Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js not found! Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo ✅ Node.js found: 
node --version

echo.
echo Checking for npm packages...
if not exist "node_modules" (
    echo 📦 Installing npm packages...
    call npm install
    if errorlevel 1 (
        echo ❌ Failed to install packages
        pause
        exit /b 1
    )
) else (
    echo ✅ Dependencies already installed
)

echo.
echo 🚀 Starting Natural Farming API Server...
echo 📊 Server will run on http://localhost:3000
echo 🌐 Website will be available at http://localhost:3000
echo 📈 API Health Check: http://localhost:3000/api/health
echo.
echo Press Ctrl+C to stop the server
echo.

node server.js
