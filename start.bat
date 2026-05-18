@echo off
echo.
echo ========================================
echo    Equence Infra Monitor
echo ========================================
echo.

where node >nul 2>nul
if %errorlevel% neq 0 (
  echo ERROR: Node.js is not installed.
  echo Download it from https://nodejs.org ^(LTS version^)
  pause
  exit /b 1
)

if not exist "node_modules" (
  echo Installing dependencies...
  npm install
  echo.
)

if not exist ".env" (
  echo First-time setup:
  node setup.js
  echo.
)

echo Starting server...
node backend/src/server.js
pause
