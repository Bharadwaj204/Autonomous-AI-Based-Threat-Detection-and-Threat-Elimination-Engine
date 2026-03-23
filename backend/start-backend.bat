@echo off
echo Starting Autonomous AI Based Threat Detection and Threat Elimination Engine Backend...
cd "threat decetion\backend"
python -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
