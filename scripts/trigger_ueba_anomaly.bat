@echo off
setlocal enabledelayedexpansion

echo ==================================================
echo UEBA CONTROLLED ANOMALY TEST
echo This script creates temporary suspicious-looking activity
echo and then cleans everything up.
echo ==================================================

set TEST_DIR=%TEMP%\ueba_anomaly_test
set TEST_USER=ueba_test_user
set TEST_PASS=TempPass123!

echo.
echo [1] Creating temporary test folder:
echo %TEST_DIR%

if exist "%TEST_DIR%" (
    rmdir /s /q "%TEST_DIR%"
)

mkdir "%TEST_DIR%"

echo.
echo [2] Creating temporary local user for failed-login testing...

net user %TEST_USER% %TEST_PASS% /add > nul 2>&1

echo.
echo [3] Generating failed authentication attempts...

for /L %%i in (1,1,15) do (
    net use \\127.0.0.1\C$ /user:%TEST_USER% WrongPassword%%i > nul 2>&1
)

echo.
echo [4] Creating suspicious test files...

for /L %%i in (1,1,40) do (
    echo echo test %%i > "%TEST_DIR%\test_script_%%i.bat"
    echo Write-Output test %%i > "%TEST_DIR%\test_script_%%i.ps1"
    echo echo test %%i > "%TEST_DIR%\test_command_%%i.cmd"
    echo dummy > "%TEST_DIR%\fake_binary_%%i.exe"
)

echo.
echo [5] Running repeated cmd.exe activity...

for /L %%i in (1,1,60) do (
    cmd /c echo CMD test %%i > nul
)

echo.
echo [6] Running repeated PowerShell activity...

for /L %%i in (1,1,60) do (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'PowerShell test %%i'" > nul
)

echo.
echo [7] Creating extra normal text files to increase file activity...

for /L %%i in (1,1,100) do (
    echo normal test file %%i > "%TEST_DIR%\normal_file_%%i.txt"
)

echo.
echo [8] Cleanup: deleting temporary test folder...

rmdir /s /q "%TEST_DIR%"

echo.
echo [9] Cleanup: deleting temporary local user...

net user %TEST_USER% /delete > nul 2>&1

echo.
echo ==================================================
echo TEST COMPLETE
echo Temporary files were deleted.
echo Temporary test user was deleted.
echo No permanent system settings were changed.
echo ==================================================

pause
endlocal