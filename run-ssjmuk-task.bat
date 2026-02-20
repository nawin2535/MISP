@echo off
REM ============================================================================
REM run-ssjmuk-task.bat - Wrapper script to run ssjmuk-task.ps1
REM ============================================================================
REM This script downloads ssjmuk-task.ps1 from GitHub and executes it
REM All scripts are pulled from GitHub automatically for easy updates
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set SCRIPT_DIR=%~dp0
set GITHUB_BASE=https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main
set PS_SCRIPT=%SCRIPT_DIR%ssjmuk-task.ps1
set MAX_RETRIES=5
set RETRY_DELAY=10

echo ============================================================================
echo Sysmon Task Runner - Downloading from GitHub
echo ============================================================================
echo.

REM Download ssjmuk-task.ps1 from GitHub
set RETRY_COUNT=0
:DOWNLOAD_RETRY
set /a RETRY_COUNT+=1
echo [Attempt %RETRY_COUNT%/%MAX_RETRIES%] Downloading ssjmuk-task.ps1 from GitHub...

REM Create temporary PowerShell script for downloading
set TEMP_PS=%TEMP%\download-ssjmuk-task.ps1
(
    echo $ProgressPreference = 'SilentlyContinue'
    echo try {
    echo     Invoke-WebRequest -Uri '%GITHUB_BASE%/ssjmuk-task.ps1' -OutFile '%PS_SCRIPT%' -UseBasicParsing -ErrorAction Stop
    echo     Write-Host 'SUCCESS: Downloaded ssjmuk-task.ps1' -ForegroundColor Green
    echo     exit 0
    echo } catch {
    echo     Write-Host 'ERROR: Failed to download:' $_.Exception.Message -ForegroundColor Red
    echo     exit 1
    echo }
) > "%TEMP_PS%"

PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%TEMP_PS%"
set DOWNLOAD_RESULT=%ERRORLEVEL%

REM Cleanup temp file
if exist "%TEMP_PS%" del "%TEMP_PS%"

if %DOWNLOAD_RESULT% EQU 0 (
    goto :DOWNLOAD_SUCCESS
) else (
    if !RETRY_COUNT! LSS %MAX_RETRIES% (
        echo Waiting %RETRY_DELAY% seconds before retry...
        timeout /t %RETRY_DELAY% /nobreak >nul
        goto :DOWNLOAD_RETRY
    ) else (
        echo.
        echo ============================================================================
        echo ERROR: Failed to download ssjmuk-task.ps1 after %MAX_RETRIES% attempts
        echo ============================================================================
        echo Please check your internet connection and GitHub accessibility
        echo GitHub URL: %GITHUB_BASE%/ssjmuk-task.ps1
        pause
        exit /b 1
    )
)

:DOWNLOAD_SUCCESS
echo.
echo ============================================================================
echo Running ssjmuk-task.ps1 with Execution Policy Bypass
echo ============================================================================
echo.

REM Check if script file exists
if not exist "%PS_SCRIPT%" (
    echo ERROR: Script file not found: %PS_SCRIPT%
    echo Please check if download was successful
    pause
    exit /b 1
)

REM Execute the downloaded script
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
set EXIT_CODE=%ERRORLEVEL%

if %EXIT_CODE% EQU 0 (
    echo.
    echo ============================================================================
    echo Script completed successfully!
    echo ============================================================================
) else (
    echo.
    echo ============================================================================
    echo Script completed with errors. Check logs in: %SCRIPT_DIR%logs\
    echo ============================================================================
)

endlocal
exit /b %EXIT_CODE%
