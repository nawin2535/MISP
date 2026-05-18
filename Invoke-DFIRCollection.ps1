################################
## DFIR Collection Script (Background)
## รันแยกจาก block-malicious.ps1 เป็น background job
## ไม่ block Wazuh active response
################################
param(
    [string]$EventType,
    [string]$IOCValue,
    [string]$IOCType,
    [string]$AlertFile,       # path ของ temp JSON file ที่ main script บันทึกไว้
    [string]$TargetFile = "",
    [string]$ProcessImage = "",
    [string]$ProcessId = "",
    [string]$ParentImage = "",
    [string]$DestinationIp = "",
    [string]$Domain = "",
    [string]$AgentName = ""
)

$logFile  = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$dfirRoot = "C:\install-sysmon\dfir-found"

function Log-Detail {
    param([string]$msg)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - [DFIR-BG] $msg" | Out-File -FilePath $logFile -Append -Encoding utf8
}

Log-Detail "DFIR background job started: EventType=$EventType IOC=$IOCValue"

# Ensure DFIR root exists
if (-not (Test-Path $dfirRoot)) {
    New-Item -ItemType Directory -Path $dfirRoot -Force | Out-Null
}

# สร้าง output directory
$ts      = Get-Date -Format 'yyyyMMdd_HHmmss'
$safeIOC = ($IOCValue -replace '[\\/:*?"<>|]', '_')
if ($safeIOC.Length -gt 32) { $safeIOC = $safeIOC.Substring(0,32) }
$dateDir = Get-Date -Format 'yyyyMMdd'
$dfirDir = Join-Path $dfirRoot "$dateDir\${EventType}_${ts}_${safeIOC}"

try {
    New-Item -ItemType Directory -Path $dfirDir -Force | Out-Null
    Log-Detail "Created: $dfirDir"
} catch {
    Log-Detail "Cannot create directory: $($_.Exception.Message)"
    exit 1
}

$artifacts = @()

# ---- 1. Raw Alert JSON ----
if ($AlertFile -and (Test-Path $AlertFile)) {
    try {
        Copy-Item $AlertFile (Join-Path $dfirDir "raw_alert.json") -Force
        Remove-Item $AlertFile -Force -ErrorAction SilentlyContinue   # cleanup temp
        $artifacts += "raw_alert.json"
        Log-Detail "Saved raw_alert.json"
    } catch {
        Log-Detail "raw_alert.json failed: $($_.Exception.Message)"
    }
}

# ---- 2. System Info ----
try {
    $os = Get-CimInstance Win32_OperatingSystem
    # กรอง NT VIRTUAL MACHINE ออก เหลือเฉพาะ user จริง
    $realUsers = @(Get-CimInstance Win32_LoggedOnUser |
        ForEach-Object { "$($_.Antecedent.Domain)\$($_.Antecedent.Name)" } |
        Where-Object { $_ -notmatch '^NT VIRTUAL MACHINE\\' } |
        Select-Object -Unique)
    @{
        hostname        = $env:COMPUTERNAME
        os_caption      = $os.Caption
        os_build        = $os.BuildNumber
        collection_time = (Get-Date -Format 'o')
        uptime_hours    = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 2)
        logged_on_users = $realUsers
    } | ConvertTo-Json | Out-File (Join-Path $dfirDir "system_info.json") -Encoding utf8
    $artifacts += "system_info.json"
    Log-Detail "Saved system_info.json"
} catch { Log-Detail "system_info.json failed: $($_.Exception.Message)" }

# ---- 3. File Artifact ----
# system binary paths ที่ไม่ต้อง copy (ใหญ่ + ไม่มีคุณค่า DFIR)
$sysBinaryPaths = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\WinSxS",
    "C:\Windows\assembly"
)

foreach ($fp in @($TargetFile, $ProcessImage) | Where-Object { $_ -and (Test-Path $_) }) {
    try {
        $isSystemBinary = $sysBinaryPaths | Where-Object { $fp.ToLower().StartsWith($_.ToLower()) }

        $fh   = Get-FileHash $fp -Algorithm SHA256
        $fhmd = Get-FileHash $fp -Algorithm MD5
        $fi   = Get-Item $fp
        $meta = [ordered]@{
            path           = $fp
            sha256         = $fh.Hash
            md5            = $fhmd.Hash
            size_bytes     = $fi.Length
            created_utc    = $fi.CreationTimeUtc.ToString('o')
            modified_utc   = $fi.LastWriteTimeUtc.ToString('o')
            owner          = (Get-Acl $fp -ErrorAction SilentlyContinue).Owner
            is_system_binary = [bool]$isSystemBinary
        }
        $safeName = ($fp -replace '[\\/:*?"<>|]','_') + "_meta.json"
        $meta | ConvertTo-Json | Out-File (Join-Path $dfirDir $safeName) -Encoding utf8
        $artifacts += $safeName

        # copy เฉพาะไฟล์ที่ไม่ใช่ system binary
        if (-not $isSystemBinary) {
            $copyName = [System.IO.Path]::GetFileName($fp) + "_DFIR_COPY"
            Copy-Item $fp (Join-Path $dfirDir $copyName) -Force -ErrorAction SilentlyContinue
            if (Test-Path (Join-Path $dfirDir $copyName)) {
                $artifacts += $copyName
                Log-Detail "Copied file artifact: $copyName"
            }
        } else {
            Log-Detail "Skipped copy (system binary): $fp"
        }
    } catch { Log-Detail "File artifact failed ($fp): $($_.Exception.Message)" }
}

# ---- 4. Process Snapshot (filtered) ----
# เก็บเฉพาะ process ที่น่าสนใจ DFIR:
#   - ไม่มี ExecutablePath (hollow/injected process)
#   - ExecutablePath อยู่นอก Windows system directories
#   - ExecutablePath อยู่ใน user temp/appdata/download paths
try {
    $sysProcessPaths = @(
        "C:\Windows\System32",
        "C:\Windows\SysWOW64",
        "C:\Windows\WinSxS",
        "C:\Program Files\WindowsApps"
    )

    $allProcs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
        Select-Object Id, ProcessName, UserName, CPU, WorkingSet,
            @{N='ExecutablePath';E={$_.Path}},
            @{N='StartTime';E={try{$_.StartTime.ToString('o')}catch{$null}}}

    $suspiciousProcs = $allProcs | Where-Object {
        $path = $_.ExecutablePath
        if (-not $path) { return $true }   # ไม่มี path = suspicious
        $isKnownSystem = $sysProcessPaths | Where-Object { $path.ToLower().StartsWith($_.ToLower()) }
        return (-not $isKnownSystem)       # เอาเฉพาะที่ไม่ใช่ system path
    }

    $suspiciousProcs | ConvertTo-Json -Depth 5 |
        Out-File (Join-Path $dfirDir "process_list.json") -Encoding utf8
    $artifacts += "process_list.json"
    Log-Detail "Saved process_list.json ($($suspiciousProcs.Count) non-system processes of $($allProcs.Count) total)"
} catch {
    Log-Detail "process_list.json failed: $($_.Exception.Message)"
    try {
        Get-Process -ErrorAction SilentlyContinue |
            Select-Object Id, ProcessName, CPU, WorkingSet |
            ConvertTo-Json |
            Out-File (Join-Path $dfirDir "process_list.json") -Encoding utf8
    } catch {}
}

# ---- 5. Network Connections (filtered) ----
# เก็บเฉพาะ TCP ESTABLISHED ที่ RemoteAddress ไม่ใช่ loopback/unroutable
try {
    $pidToName2 = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $pidToName2[$_.Id] = $_.ProcessName }

    $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object {
            $_.State -eq 'Established' -and
            $_.RemoteAddress -notmatch '^(127\.|0\.0\.0\.0|::1|$)'
        } |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
            @{N='PID';E={$_.OwningProcess}},
            @{N='ProcessName';E={if($pidToName2.ContainsKey($_.OwningProcess)){$pidToName2[$_.OwningProcess]}else{'N/A'}}}

    # UDP: เก็บเฉพาะที่ port ไม่ใช่ loopback
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notmatch '^(127\.|::1)' } |
        Select-Object LocalAddress, LocalPort,
            @{N='RemoteAddress';E={'*'}}, @{N='RemotePort';E={'*'}},
            @{N='State';E={'UDP'}},
            @{N='PID';E={$_.OwningProcess}},
            @{N='ProcessName';E={if($pidToName2.ContainsKey($_.OwningProcess)){$pidToName2[$_.OwningProcess]}else{'N/A'}}}

    @{tcp=$tcp; udp=$udp} | ConvertTo-Json -Depth 5 |
        Out-File (Join-Path $dfirDir "network_connections.json") -Encoding utf8
    $artifacts += "network_connections.json"
    Log-Detail "Saved network_connections.json (TCP ESTABLISHED external: $($tcp.Count), UDP: $($udp.Count))"
} catch { Log-Detail "network_connections.json failed: $($_.Exception.Message)" }

# ---- 6. DNS Cache ----
try {
    Get-DnsClientCache -ErrorAction SilentlyContinue |
        Select-Object Entry, RecordName, RecordType, TimeToLive, Data |
        ConvertTo-Json |
        Out-File (Join-Path $dfirDir "dns_cache.json") -Encoding utf8
    $artifacts += "dns_cache.json"
    Log-Detail "Saved dns_cache.json"
} catch { Log-Detail "dns_cache.json failed: $($_.Exception.Message)" }

# ---- 7. Registry Autoruns ----
# ใช้ Start-Job + timeout 30 วินาที เพราะ ConvertTo-Json registry values อาจช้ามาก
try {
    $regJob = Start-Job -ScriptBlock {
        param($dfirDir)
        $regKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        $autoruns = @{}
        foreach ($key in $regKeys) {
            try {
                $v = Get-ItemProperty $key -ErrorAction SilentlyContinue
                if ($v) {
                    # ดึงเฉพาะ string/numeric values ไม่เอา PSObject metadata
                    $clean = @{}
                    $v.PSObject.Properties |
                        Where-Object { $_.Name -notmatch '^PS' } |
                        ForEach-Object { $clean[$_.Name] = [string]$_.Value }
                    $autoruns[$key] = $clean
                }
            } catch {}
        }
        @{registry_autoruns = $autoruns} |
            ConvertTo-Json -Depth 4 |
            Out-File (Join-Path $dfirDir "persistence_autoruns.json") -Encoding utf8
    } -ArgumentList $dfirDir

    $completed = Wait-Job $regJob -Timeout 30
    if ($completed) {
        Receive-Job $regJob | Out-Null
        $artifacts += "persistence_autoruns.json"
        Log-Detail "Saved persistence_autoruns.json"
    } else {
        Stop-Job $regJob -ErrorAction SilentlyContinue
        Log-Detail "persistence_autoruns.json TIMEOUT (>30s) - skipped"
    }
    Remove-Job $regJob -Force -ErrorAction SilentlyContinue
} catch { Log-Detail "persistence_autoruns.json failed: $($_.Exception.Message)" }

# ---- 8. Windows Event Log (System + Sysmon 30 min) ----
# ใช้ Start-Job + timeout 60 วินาที เพื่อป้องกันค้างเมื่อ log ใหญ่
try {
    $since = (Get-Date).AddMinutes(-30)
    $evtJob = Start-Job -ScriptBlock {
        param($since, $dfirDir)
        $evtLogs = @{}
        foreach ($logName in @("System","Microsoft-Windows-Sysmon/Operational")) {
            try {
                $evtLogs[$logName] = @(
                    Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$since} `
                        -MaxEvents 100 -ErrorAction SilentlyContinue |
                    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName
                )
            } catch { $evtLogs[$logName] = @() }
        }
        $evtLogs | ConvertTo-Json -Depth 6 |
            Out-File (Join-Path $dfirDir "windows_events_30min.json") -Encoding utf8
        return $evtLogs.Keys | ForEach-Object { "$_`: $($evtLogs[$_].Count) events" }
    } -ArgumentList $since, $dfirDir

    # รอไม่เกิน 60 วินาที
    $completed = Wait-Job $evtJob -Timeout 60
    if ($completed) {
        $result = Receive-Job $evtJob
        $artifacts += "windows_events_30min.json"
        Log-Detail "Saved windows_events_30min.json ($($result -join ', '))"
    } else {
        Stop-Job $evtJob -ErrorAction SilentlyContinue
        Log-Detail "windows_events_30min.json TIMEOUT (>60s) - skipped"
    }
    Remove-Job $evtJob -Force -ErrorAction SilentlyContinue
} catch { Log-Detail "windows_events_30min.json failed: $($_.Exception.Message)" }

# ---- 9. Event-specific ----

# Event 26: Sysmon archive
if ($EventType -eq "Event26" -and $IOCValue) {
    foreach ($archDir in @("C:\Sysmon","C:\Windows\Sysmon","C:\ProgramData\Sysmon")) {
        $archivedPath = Join-Path $archDir $IOCValue
        if (Test-Path $archivedPath) {
            Copy-Item $archivedPath (Join-Path $dfirDir "event26_sysmon_archive_COPY") -Force
            $artifacts += "event26_sysmon_archive_COPY"
            Log-Detail "Copied Sysmon archive: $archivedPath"
            break
        }
    }
}

# Event 15/29: ADS streams
if ($EventType -in @("Event15","Event29") -and $TargetFile -and (Test-Path $TargetFile)) {
    try {
        Get-Item $TargetFile -Stream * -ErrorAction SilentlyContinue |
            Select-Object Stream, Length |
            ConvertTo-Json |
            Out-File (Join-Path $dfirDir "${EventType}_ads_streams.json") -Encoding utf8
        $artifacts += "${EventType}_ads_streams.json"
    } catch {}
}

# Event 22: hosts + DNS servers
if ($EventType -eq "Event22") {
    try {
        Get-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
            Out-File (Join-Path $dfirDir "event22_hosts_file.txt") -Encoding utf8
        Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
            Select-Object InterfaceAlias, AddressFamily, ServerAddresses |
            ConvertTo-Json |
            Out-File (Join-Path $dfirDir "event22_dns_servers.json") -Encoding utf8
        $artifacts += "event22_hosts_file.txt","event22_dns_servers.json"
    } catch {}
}

# ---- 10. Summary ----
try {
    @{
        dfir_timestamp = (Get-Date -Format 'o')
        event_type     = $EventType
        agent_hostname = $AgentName
        ioc_value      = $IOCValue
        ioc_type       = $IOCType
        target_file    = $TargetFile
        process_image  = $ProcessImage
        process_id     = $ProcessId
        parent_image   = $ParentImage
        dfir_artifacts = $artifacts
    } | ConvertTo-Json -Depth 8 |
        Out-File (Join-Path $dfirDir "dfir_summary.json") -Encoding utf8
    Log-Detail "DFIR complete → $dfirDir"
} catch { Log-Detail "dfir_summary.json failed: $($_.Exception.Message)" }
