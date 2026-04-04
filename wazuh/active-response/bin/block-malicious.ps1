################################
## Wazuh Active Response (FINAL)
## Supports: MISP + Sysmon + FIM
## Sysmon Events: 1, 3, 6, 7, 15, 22, 26, 29
################################

$logFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Log-Detail {
    param([string]$msg)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $msg" | Out-File -FilePath $logFile -Append -Encoding utf8
}

Log-Detail "=== AR SCRIPT STARTED (PowerShell) ==="

# =========================
# 1. Read STDIN
# =========================
$inputJson = ""

try {
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    $inputJson = Read-Host
    Log-Detail "Read-Host success. Length: $($inputJson.Length)"
} catch {
    Log-Detail "Read-Host failed: $($_.Exception.Message)"
}

# fallback
if ([string]::IsNullOrWhiteSpace($inputJson)) {
    try {
        $lines = @()
        while ($line = [Console]::In.ReadLine()) {
            $lines += $line
        }
        $inputJson = $lines -join "`n"
        Log-Detail "Fallback read success. Length: $($inputJson.Length)"
    } catch {
        Log-Detail "Fallback failed"
    }
}

if ([string]::IsNullOrWhiteSpace($inputJson)) {
    Log-Detail "CRITICAL: Empty input"
    exit 1
}

# preview log
$preview = if ($inputJson.Length -gt 2000) { $inputJson.Substring(0,2000) + "..." } else { $inputJson }
Log-Detail "INPUT PREVIEW:"
Log-Detail $preview
#Log-Detail $inputJson

# =========================
# 2. Parse JSON
# =========================
try {
    $INPUT_ARRAY = $inputJson | ConvertFrom-Json
    Log-Detail "JSON parsed OK"
} catch {
    Log-Detail "JSON parse failed"
    exit 1
}

$command = $INPUT_ARRAY.command
$alert   = $INPUT_ARRAY.parameters.alert

# =========================
# 3. Extract IOC (3 Modes)
# =========================
$IOCvalue = $null
$IOCtype  = $null

# 🔴 Mode 1: MISP
if ($alert.data.misp) {
    $IOCvalue = $alert.data.misp.value
    $IOCtype  = $alert.data.misp.type
    Log-Detail "Mode: MISP"
}

# 🟢 Mode 2: Sysmon - รองรับทั้ง .hash (Event 15) และ .hashes (Event 1,6,7)
$eventID  = $alert.data.win.system.eventID
$hashField = $alert.data.win.eventdata.hashes

if (-not $hashField) {
    $hashField = $alert.data.win.eventdata.hash
}

if ($hashField -match "SHA256=([A-Fa-f0-9]+)") {
    $IOCvalue = $matches[1]
    $IOCtype  = "sha256"
    Log-Detail "Mode: Sysmon (EventID=$eventID)"
}

# 🟡 Mode 3: Syscheck (FIM)
if ($alert.syscheck.sha256_after) {
    $IOCvalue = $alert.syscheck.sha256_after
    $IOCtype  = "sha256"
    Log-Detail "Mode: Syscheck (FIM)"
}


if (-not $IOCvalue) {
    Log-Detail "No IOC found → EXIT"
    exit 0
}

Log-Detail "IOC: $IOCvalue"

# =========================
# 4. Extract Fields
# =========================

# Sysmon
$imagePath  = $alert.data.win.eventdata.image
$processId  = $alert.data.win.eventdata.processId

# Syscheck
$filePath   = $alert.syscheck.path

Log-Detail "Sysmon Image: $imagePath"
Log-Detail "Syscheck Path: $filePath"

# =========================
# 5. FILE RESPONSE (Sysmon)
# =========================
if ($IOCtype -eq "sha256" -and $imagePath) {

    if (Test-Path $imagePath) {

        try {
            $fileHash = (Get-FileHash $imagePath -Algorithm SHA256).Hash

            if ($fileHash -eq $IOCvalue) {

                Log-Detail "Sysmon HASH MATCH → action"

                if ($processId) {
                    try {
                        Stop-Process -Id $processId -Force
                        Log-Detail "Killed PID: $processId"
                    } catch {
                        Log-Detail "Kill failed"
                    }
                }

                try {
                    Remove-Item $imagePath -Force
                    Log-Detail "Deleted file: $imagePath"
                } catch {
                    Log-Detail "Delete failed"
                }
            }

        } catch {
            Log-Detail "Sysmon handling error"
        }
    }
}


# =========================
# 5b. PROCESS RESPONSE (Sysmon Event 1)
# =========================
# $eventID = $alert.data.win.system.eventID

if ($IOCtype -eq "sha256" -and $eventID -eq "1") {
    $imagePath = $alert.data.win.eventdata.image
    $processId = $alert.data.win.eventdata.processId

    Log-Detail "Event 1: Malicious process detected - $imagePath (PID=$processId)"

    # Kill process ตาม PID ที่ได้จาก alert โดยตรง
    if ($processId) {
        try {
            Stop-Process -Id $processId -Force
            Log-Detail "Killed PID: $processId"
        } catch {
            Log-Detail "Kill PID failed: $($_.Exception.Message)"
        }
    }

    # Kill process อื่นที่รัน executable เดียวกัน
    if ($imagePath) {
        try {
            $procs = Get-CimInstance Win32_Process | Where-Object {
                $_.ExecutablePath -eq $imagePath
            }
            foreach ($p in $procs) {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                Log-Detail "Killed matching process PID: $($p.ProcessId)"
            }
        } catch {
            Log-Detail "Kill by path failed: $($_.Exception.Message)"
        }
    }

    Start-Sleep -Seconds 1

    # ลบ executable
    if ($imagePath -and (Test-Path $imagePath)) {
        try {
            Remove-Item $imagePath -Force
            Log-Detail "Deleted executable: $imagePath"
        } catch {
            Log-Detail "Delete failed: $($_.Exception.Message)"
        }
    }
}

# =========================
# 5c. DRIVER RESPONSE (Sysmon Event 6)
# =========================
if ($IOCtype -eq "sha256" -and $eventID -eq "6") {
    $driverPath = $alert.data.win.eventdata.imageLoaded

    Log-Detail "Event 6: Malicious driver detected - $driverPath"

    # ⚠️ ลบ driver ตรงๆ ไม่ได้เพราะ kernel lock อยู่
    # ต้อง schedule ลบตอน reboot แทน
    if ($driverPath -and (Test-Path $driverPath)) {
        try {
            # MoveFileEx API - ลบตอน reboot
            $code = @"
using System;
using System.Runtime.InteropServices;
public class FileHelper {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName,
        string lpNewFileName, int dwFlags);
    public const int MOVEFILE_DELAY_UNTIL_REBOOT = 4;
}
"@
            Add-Type -TypeDefinition $code
            $result = [FileHelper]::MoveFileEx($driverPath, $null,
                [FileHelper]::MOVEFILE_DELAY_UNTIL_REBOOT)

            if ($result) {
                Log-Detail "Scheduled driver delete on reboot: $driverPath"
            } else {
                Log-Detail "MoveFileEx failed"
            }
        } catch {
            Log-Detail "Driver delete error: $($_.Exception.Message)"
        }
    }

    # Disable driver service ถ้ามี
    try {
        $driverName = [System.IO.Path]::GetFileNameWithoutExtension($driverPath)
        $svc = Get-Service -Name $driverName -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $driverName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $driverName -StartupType Disabled
            Log-Detail "Disabled driver service: $driverName"
        }
    } catch {
        Log-Detail "Service disable error: $($_.Exception.Message)"
    }
}

# =========================
# 5d. DLL RESPONSE (Sysmon Event 7)
# =========================
if ($IOCtype -eq "sha256" -and $eventID -eq "7") {
    $dllPath   = $alert.data.win.eventdata.imageLoaded
    $procImage = $alert.data.win.eventdata.image

    Log-Detail "Event 7: Malicious DLL detected - $dllPath"
    Log-Detail "Loaded by process: $procImage"

    # Kill process ที่โหลด DLL นี้อยู่ก่อน
    try {
        $procs = Get-CimInstance Win32_Process | Where-Object {
            $_.ExecutablePath -eq $procImage
        }
        foreach ($p in $procs) {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Log-Detail "Killed process PID: $($p.ProcessId) ($($p.Name))"
        }
    } catch {
        Log-Detail "Kill process failed: $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 2

    # ลบ DLL
    if ($dllPath -and (Test-Path $dllPath)) {
        try {
            Remove-Item $dllPath -Force
            Log-Detail "Deleted DLL: $dllPath"
        } catch {
            # DLL อาจยัง lock อยู่ - schedule ลบตอน reboot
            try {
                $code = @"
using System;
using System.Runtime.InteropServices;
public class FileHelper2 {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName,
        string lpNewFileName, int dwFlags);
    public const int MOVEFILE_DELAY_UNTIL_REBOOT = 4;
}
"@
                Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
                $result = [FileHelper2]::MoveFileEx($dllPath, $null,
                    [FileHelper2]::MOVEFILE_DELAY_UNTIL_REBOOT)
                if ($result) {
                    Log-Detail "Scheduled DLL delete on reboot: $dllPath"
                }
            } catch {
                Log-Detail "Schedule delete failed: $($_.Exception.Message)"
            }
        }
    }
}


# =========================
# 5. FILE RESPONSE (Sysmon Event 15)
# =========================

if ($IOCtype -eq "sha256" -and $eventID -eq "15") {

    $targetFile = $alert.data.win.eventdata.targetFilename
    Log-Detail "Sysmon targetFilename: $targetFile"
    if (Test-Path $targetFile) {
        try {
            $fileHash = (Get-FileHash $targetFile -Algorithm SHA256).Hash
            Log-Detail "File hash: $fileHash"
            Log-Detail "IOC hash:  $IOCvalue"

            if ($fileHash -eq $IOCvalue) {
                Log-Detail "HASH MATCH → kill processes then delete"

                # Kill process ที่เปิดไฟล์นี้อยู่ผ่าน handle
                try {
                    $processes = Get-CimInstance Win32_Process | Where-Object {
                        $_.CommandLine -like "*$targetFile*"
                    }
                    foreach ($proc in $processes) {
                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                        Log-Detail "Killed PID: $($proc.ProcessId) ($($proc.Name))"
                    }
                } catch {
                    Log-Detail "Kill by CommandLine failed: $($_.Exception.Message)"
                }

                # ใช้ handle64.exe ถ้ามี (Sysinternals) เพื่อ release file lock
                $handleExe = "C:\Tools\handle64.exe"
                if (Test-Path $handleExe) {
                    try {
                        $handleOutput = & $handleExe -accepteula -nobanner "$targetFile" 2>&1
                        foreach ($line in $handleOutput) {
                            if ($line -match "pid: (\d+)") {
                                $pidProcess = $matches[1]
                                Stop-Process -Id $pidProcess -Force -ErrorAction SilentlyContinue
                                Log-Detail "Killed handle PID: $pidProcess"
                            }
                        }
                    } catch {
                        Log-Detail "handle64 failed: $($_.Exception.Message)"
                    }
                }

                # รอให้ process ปิดก่อนลบ
                Start-Sleep -Seconds 2

                # ลบไฟล์
                try {
                    Remove-Item $targetFile -Force
                    Log-Detail "Deleted: $targetFile"
                } catch {
                    # ถ้าลบไม่ได้ ให้ schedule ลบตอน reboot
                    try {
                        $null = Start-Process "cmd.exe" -ArgumentList "/c del /f /q `"$targetFile`"" -WindowStyle Hidden
                        Log-Detail "Scheduled delete via cmd: $targetFile"
                    } catch {
                        Log-Detail "Delete failed: $($_.Exception.Message)"
                    }
                }

            } else {
                Log-Detail "Hash mismatch - no action"
            }
        } catch {
            Log-Detail "Error: $($_.Exception.Message)"
        }
    } else {
        Log-Detail "targetFile not found: $targetFile"
    }
}

# =========================
# 5e. FILE RESPONSE (Sysmon Event 29 - File Executable Detected)
# =========================
# Event 29: Sysmon ตรวจเจอไฟล์ executable ถูกเขียนลง disk
# ใช้ targetFilename + hashes เหมือน Event 15
# ไฟล์ยังอยู่บน disk → verify hash แล้วลบทิ้ง

if ($IOCtype -eq "sha256" -and $eventID -eq "29") {

    $targetFile = $alert.data.win.eventdata.targetFilename
    Log-Detail "Event 29 (File Executable Detected): $targetFile"

    if ($targetFile -and (Test-Path $targetFile)) {
        try {
            $fileHash = (Get-FileHash $targetFile -Algorithm SHA256).Hash
            Log-Detail "File hash: $fileHash"
            Log-Detail "IOC hash:  $IOCvalue"

            if ($fileHash -eq $IOCvalue) {
                Log-Detail "HASH MATCH (Event 29) → kill parent process then delete"

                # Kill process ที่เขียนไฟล์นี้ (image = parent process)
                $parentImage = $alert.data.win.eventdata.image
                if ($parentImage) {
                    try {
                        $procs = Get-CimInstance Win32_Process | Where-Object {
                            $_.ExecutablePath -eq $parentImage
                        }
                        foreach ($p in $procs) {
                            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                            Log-Detail "Killed parent process PID: $($p.ProcessId) ($parentImage)"
                        }
                    } catch {
                        Log-Detail "Kill parent process failed: $($_.Exception.Message)"
                    }
                }

                # Kill process ใดๆ ที่รันไฟล์นี้อยู่แล้ว
                try {
                    $procs2 = Get-CimInstance Win32_Process | Where-Object {
                        $_.ExecutablePath -eq $targetFile
                    }
                    foreach ($p in $procs2) {
                        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                        Log-Detail "Killed running target PID: $($p.ProcessId)"
                    }
                } catch {
                    Log-Detail "Kill target process failed: $($_.Exception.Message)"
                }

                Start-Sleep -Seconds 2

                # ลบไฟล์
                try {
                    Remove-Item $targetFile -Force
                    Log-Detail "Deleted (Event 29): $targetFile"
                } catch {
                    # ถ้าลบไม่ได้ทันที ให้ schedule ลบตอน reboot
                    try {
                        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FileHelper29 {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName,
        string lpNewFileName, int dwFlags);
    public const int MOVEFILE_DELAY_UNTIL_REBOOT = 4;
}
"@ -ErrorAction SilentlyContinue
                        $result = [FileHelper29]::MoveFileEx($targetFile, $null,
                            [FileHelper29]::MOVEFILE_DELAY_UNTIL_REBOOT)
                        if ($result) {
                            Log-Detail "Scheduled delete on reboot (Event 29): $targetFile"
                        } else {
                            Log-Detail "MoveFileEx failed (Event 29)"
                        }
                    } catch {
                        Log-Detail "Schedule delete failed (Event 29): $($_.Exception.Message)"
                    }
                }

            } else {
                Log-Detail "Hash mismatch (Event 29) - no action"
            }
        } catch {
            Log-Detail "Event 29 handling error: $($_.Exception.Message)"
        }
    } else {
        Log-Detail "targetFile not found (Event 29): $targetFile"
    }
}

# =========================
# 5f. FILE RESPONSE (Sysmon Event 26 - File Delete Detected)
# =========================
# Event 26: Sysmon บันทึกว่าไฟล์ถูกลบไปแล้ว (อาจถูก archive ไว้ใน Sysmon archive dir)
# ไฟล์ต้นทางหายแล้ว → ตรวจสอบ Sysmon archive แล้วลบทิ้ง + log ไว้เป็นหลักฐาน

if ($IOCtype -eq "sha256" -and $eventID -eq "26") {

    $targetFile = $alert.data.win.eventdata.targetFilename
    Log-Detail "Event 26 (File Delete Detected): $targetFile"

    # ตรวจว่าไฟล์ต้นทางยังหลงเหลืออยู่หรือไม่ (บางกรณี Sysmon log ช้า)
    if ($targetFile -and (Test-Path $targetFile)) {
        try {
            $fileHash = (Get-FileHash $targetFile -Algorithm SHA256).Hash
            Log-Detail "File hash (still present): $fileHash"
            Log-Detail "IOC hash: $IOCvalue"

            if ($fileHash -eq $IOCvalue) {
                Log-Detail "HASH MATCH (Event 26) - original file still exists → delete"
                try {
                    Remove-Item $targetFile -Force
                    Log-Detail "Deleted original file (Event 26): $targetFile"
                } catch {
                    Log-Detail "Delete failed (Event 26): $($_.Exception.Message)"
                }
            } else {
                Log-Detail "Hash mismatch (Event 26) - no action on original"
            }
        } catch {
            Log-Detail "Event 26 hash check error: $($_.Exception.Message)"
        }
    } else {
        Log-Detail "Original file already gone (Event 26) - checking Sysmon archive"
    }

    # ตรวจ Sysmon archive directory (default: C:\Sysmon\)
    # Sysmon จะ archive ไฟล์ที่ถูกลบในชื่อ SHA256 hash ของไฟล์นั้น
    $sysmonArchiveDirs = @(
        "C:\Sysmon",
        "C:\Windows\Sysmon",
        "C:\ProgramData\Sysmon"
    )

    foreach ($archiveDir in $sysmonArchiveDirs) {
        if (Test-Path $archiveDir) {
            $archivedFile = Join-Path $archiveDir $IOCvalue
            if (Test-Path $archivedFile) {
                try {
                    Remove-Item $archivedFile -Force
                    Log-Detail "Deleted Sysmon archive copy (Event 26): $archivedFile"
                } catch {
                    Log-Detail "Delete archive failed (Event 26): $($_.Exception.Message)"
                }
            } else {
                Log-Detail "No archive copy found at: $archivedFile"
            }
        }
    }

    # Kill process ที่อาจเป็นต้นเหตุการลบไฟล์ (image = process ที่สั่ง delete)
    $parentImage = $alert.data.win.eventdata.image
    if ($parentImage) {
        Log-Detail "Event 26 triggered by process: $parentImage"
        # ไม่ kill โดยอัตโนมัติ เพราะ process อาจเป็น legitimate tool
        # แต่ log ไว้เพื่อ investigation
        Log-Detail "NOTE: Review process '$parentImage' manually if suspicious"
    }
}

# =========================
# 6. FILE RESPONSE (FIM)
# =========================
if ($IOCtype -eq "sha256" -and $filePath) {

    if (Test-Path $filePath) {
        try {
            $fileHash = (Get-FileHash $filePath -Algorithm SHA256).Hash

            if ($fileHash -eq $IOCvalue) {
                Log-Detail "FIM HASH MATCH → kill processes then delete"

                # Kill by ExecutablePath ตรงๆ
                try {
                    $processes = Get-CimInstance Win32_Process | Where-Object {
                        $_.ExecutablePath -eq $filePath
                    }
                    foreach ($proc in $processes) {
                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                        Log-Detail "Killed PID (ExecutablePath): $($proc.ProcessId)"
                    }
                } catch {
                    Log-Detail "Kill by ExecutablePath failed: $($_.Exception.Message)"
                }

                # Kill by CommandLine
                try {
                    $processes2 = Get-CimInstance Win32_Process | Where-Object {
                        $_.CommandLine -like "*$filePath*"
                    }
                    foreach ($proc in $processes2) {
                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                        Log-Detail "Killed PID (CommandLine): $($proc.ProcessId)"
                    }
                } catch {
                    Log-Detail "Kill by CommandLine failed: $($_.Exception.Message)"
                }

                # รอให้ process ปิด
                Start-Sleep -Seconds 2

                # ลบไฟล์
                try {
                    Remove-Item $filePath -Force
                    Log-Detail "Deleted: $filePath"
                } catch {
                    try {
                        $null = Start-Process "cmd.exe" -ArgumentList "/c del /f /q `"$filePath`"" -WindowStyle Hidden
                        Log-Detail "Scheduled delete via cmd: $filePath"
                    } catch {
                        Log-Detail "Delete failed: $($_.Exception.Message)"
                    }
                }

            } else {
                Log-Detail "FIM hash mismatch"
            }
        } catch {
            Log-Detail "FIM handling error: $($_.Exception.Message)"
        }
    } else {
        Log-Detail "File not found (FIM): $filePath"
    }
}

# =========================
# 7. NETWORK BLOCK (Sysmon Event 3)
# =========================
$winSystem    = $alert.data.win.system
$winEventdata = $alert.data.win.eventdata

if ($winSystem.eventID -eq '3') {

    $ip = $winEventdata.destinationIp

    if ($ip) {
        $ruleName = "Wazuh AR Block $ip"

        if ($command -eq "add") {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Outbound -Action Block `
                -RemoteAddress $ip -Protocol Any
            Log-Detail "Blocked IP: $ip"
        } elseif ($command -eq "delete") {
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            Log-Detail "Unblocked IP: $ip"
        }
    }
}

# =========================
# 8. DOMAIN BLOCK (Sysmon Event 22)
# =========================
if ($winSystem.eventID -eq '22') {

    $domain = $winEventdata.queryName
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"

    if ($domain -and -not (Select-String $hostsPath $domain -Quiet)) {
        Add-Content $hostsPath "127.0.0.1`t$domain"
        Log-Detail "Blocked domain: $domain"
    }
}

# =========================
# END
# =========================
Log-Detail "=== AR SCRIPT ENDED ==="
exit 0
