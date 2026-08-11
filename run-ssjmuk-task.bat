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

REM ============================================================================
REM JITTER: กระจายเวลาไม่ให้ทุกเครื่องดึง GitHub ชน 10:00 พร้อมกัน (กัน HTTP 429)
REM ต้องอยู่ก่อน GitHub hit แรก (self-update)
REM Gate ด้วย IsSystem: scheduled task รันเป็น SYSTEM -> jitter ยิง; admin double-click
REM test รันเป็น user -> skip (ชี้ขาดแน่นอน ไม่ขึ้นกับ session/desktop)
REM ============================================================================
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$jf='%~dp0last_jitter.txt'; if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { $s = Get-Random -Minimum 0 -Maximum 900; Set-Content -Path $jf -Value $s -Encoding ascii; Write-Host ('Jitter: sleeping ' + $s + ' sec (anti-429)...'); Start-Sleep -Seconds $s } else { Set-Content -Path $jf -Value 'skip' -Encoding ascii; Write-Host 'Not SYSTEM (manual/test) - skipping jitter' }"

REM Configuration
set SCRIPT_DIR=%~dp0
set GITHUB_BASE=https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main
REM File server (primary source) - ควรตรงกับ FileServerBaseUrl ใน ssjmuk-task.ps1
REM ว่าง = ข้าม primary ไป GitHub ตรง. FS ตาย/ช้า = timeout 10s fallback GitHub อัตโนมัติ
set FILESERVER_BASE=http://cyberupdate-mdo.moph.go.th:19080
set PS_SCRIPT=%SCRIPT_DIR%ssjmuk-task.ps1
set MAX_RETRIES=5
set RETRY_DELAY=10

REM ============================================================================
REM SELF-UPDATE: Download latest version of this script from GitHub
REM ============================================================================
echo Checking for script updates...

set SELF_NEW=%SCRIPT_DIR%run-ssjmuk-task.new.bat
set SELF_CURRENT=%~f0

REM Download latest .bat: file server primary -> GitHub fallback (size + HTML-page reject)
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ProgressPreference='SilentlyContinue'; $dst='%SELF_NEW%'; $fs='%FILESERVER_BASE%'; $gh='%GITHUB_BASE%'; $srcs=@(); if($fs -and $fs -notmatch '<host>'){ $srcs+=,@('FileServer',($fs+'/run-ssjmuk-task.bat'),10) }; $srcs+=,@('GitHub',($gh+'/run-ssjmuk-task.bat'),60); $ok=$false; foreach($s in $srcs){ try{ if(Test-Path $dst){Remove-Item $dst -Force}; Invoke-WebRequest -Uri $s[1] -OutFile $dst -UseBasicParsing -TimeoutSec $s[2] -ErrorAction Stop; $valid=(Test-Path $dst) -and ((Get-Item $dst).Length -gt 1000); if($valid){ $c=Get-Content $dst -Raw; $hd=$c.Substring(0,[Math]::Min(256,$c.Length)); if($hd -match '(?i)<html|<head|<body|Too Many Requests|Rate limit'){$valid=$false} }; if($valid){ Write-Host ('SELF-FETCH-SOURCE: '+$s[0]); $ok=$true; break } }catch{ Write-Host ('  self fetch fail from '+$s[0]) } }; if($ok){exit 0}else{exit 1}"

if %ERRORLEVEL% EQU 0 (
    REM เปรียบเทียบว่าไฟล์ต่างกันไหม
    fc /b "%SELF_CURRENT%" "%SELF_NEW%" >nul 2>&1
    if errorlevel 1 (
        echo UPDATE FOUND: Re-launching updated script...
        REM สร้าง helper bat เพื่อ overwrite แล้ว re-launch
        set UPDATER=%TEMP%\ssjmuk-updater.bat
        (
            echo @echo off
            echo timeout /t 2 /nobreak ^>nul
            echo copy /y "%SELF_NEW%" "%SELF_CURRENT%" ^>nul
            echo del "%SELF_NEW%"
            echo start "" cmd.exe /c "%SELF_CURRENT%"
        ) > "%TEMP%\ssjmuk-updater.bat"
        start "" cmd.exe /c "%TEMP%\ssjmuk-updater.bat"
        exit /b
    ) else (
        echo SUCCESS: Script is already up to date
        del "%SELF_NEW%" >nul 2>&1
    )
) else (
    echo WARNING: Could not check for updates, continuing with current version...
)

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
REM Download ssjmuk-task.ps1: file server primary -> GitHub fallback (+ parse-check)
REM stage .tmp -> integrity (size / HTML-reject / PowerShell parse) -> commit
REM ไฟล์เสีย/partial ไม่ทับตัวจริง; FS ตาย/ช้า = timeout 10s fallback GitHub อัตโนมัติ
REM ============================================================================
echo Downloading ssjmuk-task.ps1 (file server first, GitHub fallback)...

PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ProgressPreference='SilentlyContinue'; $dst='%PS_SCRIPT%'; $tmp=$dst+'.tmp'; $fs='%FILESERVER_BASE%'; $gh='%GITHUB_BASE%'; $srcs=@(); if($fs -and $fs -notmatch '<host>'){ $srcs+=,@('FileServer',($fs+'/ssjmuk-task.ps1'),10,1) }; $srcs+=,@('GitHub',($gh+'/ssjmuk-task.ps1'),60,%MAX_RETRIES%); $ok=$false; foreach($s in $srcs){ for($a=1;$a -le $s[3];$a++){ try{ if(Test-Path $tmp){Remove-Item $tmp -Force}; Invoke-WebRequest -Uri $s[1] -OutFile $tmp -UseBasicParsing -TimeoutSec $s[2] -ErrorAction Stop; $valid=$true; if(-not(Test-Path $tmp)){$valid=$false} elseif((Get-Item $tmp).Length -lt 5000){$valid=$false} else{ $c=Get-Content $tmp -Raw; if([string]::IsNullOrWhiteSpace($c)){$valid=$false} else{ $hd=$c.Substring(0,[Math]::Min(512,$c.Length)); if($hd -match '(?i)<html|<head|<body|Too Many Requests|Rate limit'){$valid=$false} else{ $t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseInput($c,[ref]$t,[ref]$e); if($e -and $e.Count -gt 0){$valid=$false} } } }; if($valid){ Move-Item $tmp $dst -Force; Write-Host ('PS-FETCH-SOURCE: '+$s[0]); $ok=$true; break } else{ Write-Host ('  ps integrity fail from '+$s[0]) } }catch{ Write-Host ('  ps fetch fail from '+$s[0]+': '+$_.Exception.Message) }; if($a -lt $s[3]){ Start-Sleep -Seconds %RETRY_DELAY% } }; if($ok){break} }; if($ok){exit 0}else{exit 1}"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ============================================================================
    echo ERROR: Failed to download ssjmuk-task.ps1 from all sources file server + GitHub
    echo ============================================================================
    pause
    exit /b 1
)
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
