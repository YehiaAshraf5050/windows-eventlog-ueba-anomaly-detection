@echo off
setlocal enabledelayedexpansion

echo ==================================================
echo UEBA CONTROLLED MULTI-SCENARIO TEST
echo Each scenario runs in a separate time window.
echo Wait time between scenarios: 12 minutes.
echo ==================================================

set TEST_DIR=%TEMP%\ueba_scenario_test
set TEST_USER=ueba_test_user
set TEST_PASS=TempPass123!

echo.
echo Preparing test directory
echo ==================================================

if exist "%TEST_DIR%" (
    rmdir /s /q "%TEST_DIR%"
)

mkdir "%TEST_DIR%"

echo Test directory:
echo %TEST_DIR%


echo.
echo Scenario 1: Failed login burst
echo ==================================================

net user %TEST_USER% %TEST_PASS% /add > nul 2>&1

for /L %%i in (1,1,15) do (
    net use \\127.0.0.1\C$ /user:%TEST_USER% WrongPassword%%i > nul 2>&1
)

net user %TEST_USER% /delete > nul 2>&1

echo Scenario 1 complete.
echo Waiting 12 minutes before next scenario...
timeout /t 720 /nobreak


echo.
echo Scenario 2: Suspicious file creation
echo ==================================================

for /L %%i in (1,1,80) do (
    echo echo test %%i > "%TEST_DIR%\test_script_%%i.bat"
    echo Write-Output test %%i > "%TEST_DIR%\test_script_%%i.ps1"
    echo echo test %%i > "%TEST_DIR%\test_command_%%i.cmd"
    echo dummy > "%TEST_DIR%\fake_binary_%%i.exe"
)

echo Scenario 2 complete.
echo Files will remain until the final cleanup step.
echo Waiting 12 minutes before next scenario...
timeout /t 720 /nobreak


echo.
echo Scenario 3: CMD execution burst
echo ==================================================

for /L %%i in (1,1,60) do (
    cmd /c echo CMD test %%i > nul
)

echo Scenario 3 complete.
echo Waiting 12 minutes before next scenario...
timeout /t 720 /nobreak


echo.
echo Scenario 4: PowerShell execution burst
echo ==================================================

for /L %%i in (1,1,60) do (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'PowerShell test %%i'" > nul
)

echo Scenario 4 complete.
echo Waiting 12 minutes before next scenario...
timeout /t 720 /nobreak


echo.
echo Scenario 5: Mixed shell and file activity
echo ==================================================

for /L %%i in (1,1,50) do (
    cmd /c echo CMD mixed test %%i > nul
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'PowerShell mixed test %%i'" > nul
    echo echo mixed %%i > "%TEST_DIR%\mixed_script_%%i.bat"
    echo Write-Output mixed %%i > "%TEST_DIR%\mixed_script_%%i.ps1"
    echo dummy > "%TEST_DIR%\mixed_binary_%%i.exe"
)

echo Scenario 5 complete.
echo Waiting 5 minutes before cleanup so final events can be shipped...
timeout /t 300 /nobreak


echo.
echo Final cleanup: deleting temporary test folder
echo ==================================================

if exist "%TEST_DIR%" (
    rmdir /s /q "%TEST_DIR%"
)

echo Cleanup complete.

pause
endlocal