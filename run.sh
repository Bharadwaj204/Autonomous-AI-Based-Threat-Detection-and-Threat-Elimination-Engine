#!/bin/bash
echo "======================================================="
echo "    THREAT SENTINEL - Autonomous AI Security Engine    "
echo "======================================================="
echo ""
echo "Cleaning up old logs and quarantine files..."
rm -f backend/data/logs/*.log
rm -f backend/data/quarantine/*
echo ""
echo "[1/2] Starting Backend (FastAPI + AI Models)..."
cd backend
python3 start_server.py &
BACKEND_PID=$!
cd ..

echo "[2/2] Starting React Frontend..."
cd frontend
npm run dev &
FRONTEND_PID=$!

echo ""
echo "Launch sequence complete. Press CTRL+C to terminate both servers."
wait $BACKEND_PID $FRONTEND_PID
