@echo off
set PYTHONIOENCODING=utf-8
color 0b
title THREAT SENTINEL - Main Launcher

echo =======================================================
echo     THREAT SENTINEL - Autonomous AI Security Engine    
echo =======================================================
echo.
echo [1/3] Cleaning up old logs and quarantine files...
if exist backend\data\logs\*.log del /q backend\data\logs\*.log
if exist backend\data\quarantine\*.* del /q backend\data\quarantine\*.*

echo.
echo [2/3] Starting Backend (FastAPI + AI Models) on Port 8000...
start "ThreatSentinel Backend (Port 8000)" cmd /k "cd backend && title ThreatSentinel Backend && python start_server.py"

echo [3/3] Starting React Frontend on Port 5173...
start "ThreatSentinel Frontend (Port 5173)" cmd /k "cd frontend && title ThreatSentinel Frontend && npm run dev"

echo.
echo =======================================================
echo   [SUCCESS] Launch sequence complete!
echo   - Backend is launching in a new window.
echo   - Frontend is launching in a new window.
echo.
echo   You can safely close this main launcher window.
echo =======================================================
pause
