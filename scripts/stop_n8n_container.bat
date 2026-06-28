@echo off

echo ============================================
echo STOPPING N8N CONTAINER
echo ============================================

docker stop <N8N_CONTAINER_NAME>

echo.
echo ============================================
echo N8N CONTAINER STOPPED
echo ============================================

pause