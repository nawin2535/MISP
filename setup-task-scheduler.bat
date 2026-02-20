@echo off
REM ============================================================================
REM setup-task-scheduler.bat - Setup Task Scheduler Wrapper
REM ============================================================================
REM This batch file bypasses PowerShell execution policy restrictions
REM and runs setup-task-scheduler.ps1
REM ============================================================================

setlocal

set SCRIPT_DIR=%~dp0
set PS_SCRIPT=%SCRIPT_DIR%setup-task-scheduler.ps1

echo ============================================================================
echo Task Scheduler Setup for Sysmon Config Update
echo ============================================================================
echo.
echo This will create a scheduled task to run run-ssjmuk-task.bat daily at 10:00 AM
echo.
echo NOTE: This script must be run as Administrator!
echo.

REM Check if PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo ERROR: PowerShell script not found: %PS_SCRIPT%
    pause
    exit /b 1
)

REM Run PowerShell script with Execution Policy Bypass
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"

set EXIT_CODE=%ERRORLEVEL%

if %EXIT_CODE% EQU 0 (
    echo.
    echo ============================================================================
    echo Setup completed successfully!
    echo ============================================================================
) else (
    echo.
    echo ============================================================================
    echo Setup completed with errors. Please check the messages above.
    echo ============================================================================
)

endlocal
exit /b %EXIT_CODE%
