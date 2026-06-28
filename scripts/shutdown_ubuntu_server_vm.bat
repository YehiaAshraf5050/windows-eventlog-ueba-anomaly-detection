@echo off

echo ============================================
echo SHUTTING DOWN UBUNTU SERVER VM
echo ============================================

ssh <UBUNTU_USER>@<UBUNTU_SERVER_IP> "sudo /usr/sbin/shutdown -h now"

echo.
echo ============================================
echo SHUTDOWN COMMAND SENT
echo ============================================

pause