@echo off

echo ============================================
echo BACKING UP UEBA PROJECT FILES
echo ============================================

cd /d "C:\Path\To\windows-eventlog-ueba-anomaly-detection"

python backup_project_files.py

echo.
echo ============================================
echo BACKUP COMPLETE
echo ============================================

pause