@echo off
set PYTHONIOENCODING=utf-8
color 0a
title ThreatSentinel AI Training

echo =======================================================
echo     THREAT SENTINEL - ML Model Training Pipeline
echo =======================================================
echo.
echo Starting AI Model Training (RandomForest + IsolationForest)...
echo This will process the dataset and train new models for the Engine.
echo.

cd backend
python ml/train_cicids.py

echo.
echo =======================================================
echo ✅ Training complete! The new models are saved in backend/models/
echo =======================================================
pause
