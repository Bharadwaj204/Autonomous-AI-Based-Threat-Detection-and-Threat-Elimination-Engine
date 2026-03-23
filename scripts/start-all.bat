@echo off
echo Starting Autonomous AI Based Threat Detection and Threat Elimination Engine...

start cmd /k "backend\start-backend.bat"
start cmd /k "frontend\start-frontend.bat"

echo Both services started!
echo Backend API: http://localhost:8000
echo Frontend Dashboard: http://localhost:5173
echo Press any key to stop all services...
pause > nul
taskkill /F /FI "WindowTitle eq Administrator:  backend\start-backend.bat" /T
taskkill /F /FI "WindowTitle eq Administrator:  frontend\start-frontend.bat" /T
echo Services stopped.
