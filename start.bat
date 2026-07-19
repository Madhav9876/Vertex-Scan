@echo off
echo ========================================
echo    Vertex Scan - Web Security Scanner
echo ========================================
echo.

:: Start Backend
echo [1/2] Starting backend server...
cd /d "%~dp0backend"
start "Vertex Scan Backend" cmd /c "node src/index.js"

:: Wait for backend to start
timeout /t 3 /nobreak >nul

:: Start Frontend
echo [2/2] Starting frontend dev server...
cd /d "%~dp0frontend"
start "Vertex Scan Frontend" cmd /c "npx vite --host"

echo.
echo ========================================
echo  Backend:  http://localhost:3001
echo  Frontend: http://localhost:5173
echo  API:      http://localhost:3001/api
echo ========================================
echo.
pause