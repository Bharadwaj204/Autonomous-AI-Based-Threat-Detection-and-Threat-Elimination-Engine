@echo off
set PYTHONIOENCODING=utf-8
color 0b
title ThreatSentinel Launcher

echo =======================================================
echo     THREAT SENTINEL - Autonomous AI Security Engine    
echo =======================================================
echo.
echo Cleaning up old logs and quarantine files...
if exist ..\backend\data\logs\*.log del /q ..\backend\data\logs\*.log
if exist ..\backend\data\quarantine\*.* del /q ..\backend\data\quarantine\*.*
echo.
echo [1/2] Starting Backend (FastAPI + AI Models) on Port 8000...
start "ThreatSentinel Backend" cmd /k "cd ..\backend && python start_server.py"

echo [2/2] Starting React Frontend on Port 5173...
start "ThreatSentinel Frontend" cmd /k "cd ..\frontend && npm run dev"

echo.
echo Launch sequence complete. Both services are booting up in separate windows.
pause
