@echo off

echo ============================================
echo DAILY UEBA DETECTION PIPELINE
echo ============================================

cd /d "C:\Path\To\windows-eventlog-ueba-anomaly-detection"

echo.
echo [1/4] Running feature engineering...
python -m src.preprocessing.feature_engineering

echo.
echo [2/4] Running anomaly detection...
python .\src\training_testing\detect_anomaly.py

echo.
echo [3/4] Extracting final anomalies...
python .\src\training_testing\extract_anomalies.py

echo.
echo [4/4] Sending anomalies to Elasticsearch and n8n...
python .\src\ingestion\send_anomalies_to_elastic.py

echo.
echo ============================================
echo DAILY DETECTION PIPELINE COMPLETE
echo ============================================

pause