@echo off

echo ============================================
echo UEBA TRAINING PIPELINE
echo ============================================

cd /d "C:\Path\To\windows-eventlog-ueba-anomaly-detection"

echo.
echo [1/2] Running feature engineering...
python -m src.preprocessing.feature_engineering

echo.
echo [2/2] Training anomaly detection models...
python .\src\training_testing\train_model.py

echo.
echo ============================================
echo TRAINING PIPELINE COMPLETE
echo ============================================

pause