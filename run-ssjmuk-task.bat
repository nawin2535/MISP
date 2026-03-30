@echo off
setlocal EnableDelayedExpansion

REM ============================================================================
REM AUTO-ELEVATE: Re-launch as Administrator if not already elevated
REM ============================================================================
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); exit ([int](-not $isAdmin))"

if errorlevel 1 (
    echo Requesting Administrator privileges...
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process cmd.exe -ArgumentList '/c \"%~f0\"' -Verb RunAs -Wait"
    exit /b
)

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

REM ============================================================================
REM AUTO-FIX PERMISSION: Grant Everyone full access (ไม่ขึ้นกับ %USERNAME%)
REM ============================================================================
echo Checking and fixing permissions for %SCRIPT_DIR%...

if not exist "%SCRIPT_DIR%" (
    mkdir "%SCRIPT_DIR%" 2>nul
    if errorlevel 1 (
        echo ERROR: Cannot create directory %SCRIPT_DIR%
        pause
        exit /b 1
    )
)

REM ใช้ BUILTIN\Users แทน %USERNAME% เพื่อให้ครอบคลุมทุก user
REM และ /grant:r เพื่อ replace permission เดิมที่อาจ deny อยู่
icacls "%SCRIPT_DIR%" /grant:r "BUILTIN\Users:(OI)(CI)F" /T >nul 2>&1
icacls "%SCRIPT_DIR%" /grant:r "NT AUTHORITY\Authenticated Users:(OI)(CI)F" /T >nul 2>&1

REM ลบ read-only attribute ของทุกไฟล์ใน folder
attrib -R "%SCRIPT_DIR%*.*" /S >nul 2>&1

echo SUCCESS: Permissions fixed

REM ============================================================================
REM PRE-FLIGHT CHECK: Verify directory is writable
REM ============================================================================
if exist "%SCRIPT_DIR%write_test.tmp" del "%SCRIPT_DIR%write_test.tmp" >nul 2>&1
echo. > "%SCRIPT_DIR%write_test.tmp" 2>nul
if errorlevel 1 (
    echo ============================================================================
    echo ERROR: Still no write permission to %SCRIPT_DIR% after auto-fix
    echo Please contact your system administrator
    echo ============================================================================
    pause
    exit /b 1
) else (
    del "%SCRIPT_DIR%write_test.tmp" >nul 2>&1
    echo SUCCESS: Directory is writable
)

echo.

REM ============================================================================
REM Download ssjmuk-task.ps1 from GitHub
REM ============================================================================
set RETRY_COUNT=0
:DOWNLOAD_RETRY
set /a RETRY_COUNT+=1
echo [Attempt %RETRY_COUNT%/%MAX_RETRIES%] Downloading ssjmuk-task.ps1 from GitHub...

PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ProgressPreference='SilentlyContinue'; try { Invoke-WebRequest -Uri '%GITHUB_BASE%/ssjmuk-task.ps1' -OutFile '%PS_SCRIPT%' -UseBasicParsing -ErrorAction Stop; Write-Host 'SUCCESS: Downloaded ssjmuk-task.ps1' -ForegroundColor Green; exit 0 } catch { Write-Host 'ERROR:' $_.Exception.Message -ForegroundColor Red; exit 1 }"

set DOWNLOAD_RESULT=%ERRORLEVEL%

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

if not exist "%PS_SCRIPT%" (
    echo ERROR: Script file not found: %PS_SCRIPT%
    pause
    exit /b 1
)

REM Clear Hidden/System attributes ก่อนรัน script
attrib -H -S "%SCRIPT_DIR%*.ps1" >nul 2>&1
attrib -H -S -I "%SCRIPT_DIR%*.ps1" >nul 2>&1

REM รัน script
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
