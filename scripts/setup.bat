@echo off
echo Setting up Autonomous AI Based Threat Detection and Threat Elimination Engine...

echo [1/3] Setting up Python Backend...
cd "autonomous-ai-based-threat-detection-and-threat-elimination-engine\backend"
pip install -r requirements.txt

echo [2/3] Generating Data and Training Models...
python datasets/generate_synthetic_data.py
python ml/train.py

echo [3/3] Setting up React Frontend...
cd "..\frontend"
call npm install

echo Setup Complete! Run start-all.bat to launch.
pause
