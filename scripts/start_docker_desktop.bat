@echo off

echo ============================================
echo STARTING DOCKER DESKTOP AND N8N
echo ============================================

start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"

echo Waiting for Docker Desktop to initialize...
timeout /t 60 /nobreak

echo Starting n8n container...
docker start <N8N_CONTAINER_NAME>

echo.
echo ============================================
echo DOCKER AND N8N STARTUP COMPLETE
echo ============================================

pause