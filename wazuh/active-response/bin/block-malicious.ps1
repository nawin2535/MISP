################################
## Wazuh Active Response (FINAL)
## Supports: MISP + Sysmon + FIM
## Sysmon Events: 1, 3, 6, 7, 15, 22, 26, 29
## DFIR Collection: C:\install-sysmon\dfir-found\
################################

$logFile  = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$dfirRoot = "C:\install-sysmon\dfir-found"

function Log-Detail {
    param([string]$msg)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $msg" | Out-File -FilePath $logFile -Append -Encoding utf8
}

# =========================
# DFIR Collection Function
# =========================
function Invoke-DFIRCollection {
    param(
        [string]$EventType,        # "Event1", "Event3", "Event6", "Event7", "Event15", "Event22", "Event26", "Event29", "FIM", "MISP"
        [string]$IOCValue,         # SHA256 / IP / Domain
        [string]$IOCType,          # "sha256" / "ip" / "domain"
        [string]$TargetFile,       # path ของไฟล์ที่เกี่ยวข้อง (ถ้ามี)
        [string]$ProcessImage,     # path ของ process (ถ้ามี)
        [string]$ProcessId,        # PID (ถ้ามี)
        [string]$ParentImage,      # parent process path (ถ้ามี)
        [string]$CommandLine,      # command line (ถ้ามี)
        [string]$User,             # username (ถ้ามี)
        [string]$DestinationIp,    # IP ปลายทาง (Event 3)
        [string]$DestinationPort,  # Port ปลายทาง (Event 3)
        [string]$Domain,           # Domain (Event 22)
        [string]$AgentName,        # ชื่อ agent/host
        [object]$RawAlert          # raw alert JSON object
    )

    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeEvent  = $EventType -replace '[\\/:*?"<>|]', '_'
    $safeIOC    = $IOCValue  -replace '[\\/:*?"<>|]', '_'
    if ($safeIOC.Length -gt 32) { $safeIOC = $safeIOC.Substring(0,32) }

    # สร้าง folder รายวัน: dfir-found\20250501\Event1_<ioc>\
    $dateFolder  = Get-Date -Format 'yyyyMMdd'
    $dfirDir     = Join-Path $dfirRoot "$dateFolder\${safeEvent}_${timestamp}_${safeIOC}"

    try {
        New-Item -ItemType Directory -Path $dfirDir -Force | Out-Null
        Log-Detail "DFIR: Created directory $dfirDir"
    } catch {
        Log-Detail "DFIR: Failed to create directory: $($_.Exception.Message)"
        return
    }

    # ---- 1. DFIR SUMMARY (JSON) ----
    $summary = [ordered]@{
        dfir_timestamp  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        event_type      = $EventType
        agent_hostname  = $AgentName
        ioc_value       = $IOCValue
        ioc_type        = $IOCType
        target_file     = $TargetFile
        process_image   = $ProcessImage
        process_id      = $ProcessId
        parent_image    = $ParentImage
        command_line    = $CommandLine
        user            = $User
        destination_ip  = $DestinationIp
        destination_port= $DestinationPort
        domain          = $Domain
        actions_taken   = @()
        dfir_artifacts  = @()
    }

    # ---- 2. เก็บ Raw Alert JSON ----
    try {
        $alertJson = $RawAlert | ConvertTo-Json -Depth 20
        $alertPath = Join-Path $dfirDir "raw_alert.json"
        $alertJson | Out-File -FilePath $alertPath -Encoding utf8
        $summary.dfir_artifacts += "raw_alert.json"
        Log-Detail "DFIR: Saved raw_alert.json"
    } catch {
        Log-Detail "DFIR: raw_alert.json failed: $($_.Exception.Message)"
    }

    # ---- 3. เก็บ System Information ----
    try {
        $sysInfo = [ordered]@{
            hostname        = $env:COMPUTERNAME
            os_version      = (Get-CimInstance Win32_OperatingSystem).Caption
            os_build        = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            collection_time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            timezone        = (Get-TimeZone).Id
            uptime_hours    = [math]::Round(((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).TotalHours, 2)
            current_user    = "$env:USERDOMAIN\$env:USERNAME"
            logged_on_users = @(
                Get-CimInstance Win32_LoggedOnUser | ForEach-Object {
                    "$($_.Antecedent.Domain)\$($_.Antecedent.Name)"
                } | Select-Object -Unique
            )
        }
        $sysInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $dfirDir "system_info.json") -Encoding utf8
        $summary.dfir_artifacts += "system_info.json"
        Log-Detail "DFIR: Saved system_info.json"
    } catch {
        Log-Detail "DFIR: system_info.json failed: $($_.Exception.Message)"
    }

    # ---- 4. FILE ARTIFACT (ถ้ามีไฟล์เป้าหมาย) ----
    foreach ($fp in @($TargetFile, $ProcessImage) | Where-Object { $_ -and (Test-Path $_) }) {
        try {
            $fh     = Get-FileHash $fp -Algorithm SHA256
            $fhMD5  = Get-FileHash $fp -Algorithm MD5
            $fi     = Get-Item $fp
            $fmeta  = [ordered]@{
                path          = $fp
                sha256        = $fh.Hash
                md5           = $fhMD5.Hash
                size_bytes    = $fi.Length
                created_utc   = $fi.CreationTimeUtc.ToString('o')
                modified_utc  = $fi.LastWriteTimeUtc.ToString('o')
                accessed_utc  = $fi.LastAccessTimeUtc.ToString('o')
                attributes    = $fi.Attributes.ToString()
                owner         = (Get-Acl $fp).Owner
                version_info  = $null
            }
            # PE Version Info
            try {
                $vi = (Get-Item $fp).VersionInfo
                $fmeta.version_info = [ordered]@{
                    file_description  = $vi.FileDescription
                    product_name      = $vi.ProductName
                    company_name      = $vi.CompanyName
                    file_version      = $vi.FileVersion
                    product_version   = $vi.ProductVersion
                    original_filename = $vi.OriginalFilename
                    internal_name     = $vi.InternalName
                }
            } catch {}

            $safeFilename = ($fp -replace '[\\/:*?"<>|]','_') + "_meta.json"
            $fmeta | ConvertTo-Json | Out-File -FilePath (Join-Path $dfirDir $safeFilename) -Encoding utf8
            $summary.dfir_artifacts += $safeFilename

            # คัดลอกไฟล์ต้นฉบับ (ก่อนถูกลบ)
            $copyName = [System.IO.Path]::GetFileName($fp) + "_DFIR_COPY"
            $copyDest = Join-Path $dfirDir $copyName
            Copy-Item -Path $fp -Destination $copyDest -Force -ErrorAction SilentlyContinue
            if (Test-Path $copyDest) {
                $summary.dfir_artifacts += $copyName
                Log-Detail "DFIR: Copied file artifact: $copyName"
                $summary.actions_taken += "Copied file: $fp"
            }
        } catch {
            Log-Detail "DFIR: File artifact failed ($fp): $($_.Exception.Message)"
        }
    }

    # ---- 5. PROCESS SNAPSHOT ----
    try {
        $procList = Get-CimInstance Win32_Process | Select-Object ProcessId, Name,
            ExecutablePath, CommandLine, ParentProcessId,
            @{N='CreationDate';E={$_.CreationDate.ToString('o')}},
            @{N='Owner';E={
                $r = $_ | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($r) { "$($r.Domain)\$($r.User)" } else { "N/A" }
            }}

        $procList | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $dfirDir "process_list.json") -Encoding utf8
        $summary.dfir_artifacts += "process_list.json"
        Log-Detail "DFIR: Saved process_list.json ($($procList.Count) processes)"
    } catch {
        Log-Detail "DFIR: process_list.json failed: $($_.Exception.Message)"
    }

    # ---- 6. NETWORK CONNECTIONS ----
    try {
        $netConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object `
            LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
            @{N='PID';E={$_.OwningProcess}},
            @{N='ProcessName';E={
                try { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } catch { "N/A" }
            }}
        $udpConns = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object `
            LocalAddress, LocalPort,
            @{N='RemoteAddress';E={'*'}},
            @{N='RemotePort';E={'*'}},
            @{N='State';E={'UDP'}},
            @{N='PID';E={$_.OwningProcess}},
            @{N='ProcessName';E={
                try { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } catch { "N/A" }
            }}

        @{ tcp = $netConns; udp = $udpConns } |
            ConvertTo-Json -Depth 5 |
            Out-File -FilePath (Join-Path $dfirDir "network_connections.json") -Encoding utf8
        $summary.dfir_artifacts += "network_connections.json"
        Log-Detail "DFIR: Saved network_connections.json"
    } catch {
        Log-Detail "DFIR: network_connections.json failed: $($_.Exception.Message)"
    }

    # ---- 7. DNS CACHE ----
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
            Select-Object Entry, RecordName, RecordType, TimeToLive, DataLength, Data
        $dnsCache | ConvertTo-Json | Out-File -FilePath (Join-Path $dfirDir "dns_cache.json") -Encoding utf8
        $summary.dfir_artifacts += "dns_cache.json"
        Log-Detail "DFIR: Saved dns_cache.json ($($dnsCache.Count) entries)"
    } catch {
        Log-Detail "DFIR: dns_cache.json failed: $($_.Exception.Message)"
    }

    # ---- 8. EVENT-SPECIFIC COLLECTION ----

    # Event 1: Process Create - เก็บ process tree + siblings
    if ($EventType -eq "Event1" -and $ProcessId) {
        try {
            $pid_int = [int]$ProcessId
            $targetProc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid_int" -ErrorAction SilentlyContinue
            $parentProc = if ($targetProc) {
                Get-CimInstance Win32_Process -Filter "ProcessId=$($targetProc.ParentProcessId)" -ErrorAction SilentlyContinue
            }
            $childProcs = Get-CimInstance Win32_Process -Filter "ParentProcessId=$pid_int" -ErrorAction SilentlyContinue
            $siblingProcs = if ($targetProc) {
                Get-CimInstance Win32_Process -Filter "ParentProcessId=$($targetProc.ParentProcessId)" -ErrorAction SilentlyContinue |
                    Where-Object { $_.ProcessId -ne $pid_int }
            }

            @{
                target  = $targetProc
                parent  = $parentProc
                children= @($childProcs)
                siblings= @($siblingProcs)
            } | ConvertTo-Json -Depth 5 |
                Out-File -FilePath (Join-Path $dfirDir "event1_process_tree.json") -Encoding utf8
            $summary.dfir_artifacts += "event1_process_tree.json"
            Log-Detail "DFIR: Saved event1_process_tree.json"
        } catch {
            Log-Detail "DFIR: Event1 process tree failed: $($_.Exception.Message)"
        }

        # เก็บ environment variables ของ process ที่ trigger
        try {
            $envVars = [System.Environment]::GetEnvironmentVariables() |
                ConvertTo-Json
            $envVars | Out-File -FilePath (Join-Path $dfirDir "event1_env_vars.json") -Encoding utf8
            $summary.dfir_artifacts += "event1_env_vars.json"
        } catch {}
    }

    # Event 3: Network - เก็บ firewall rules + routing table
    if ($EventType -eq "Event3") {
        try {
            $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                Where-Object { $_.Enabled -eq 'True' } |
                Select-Object DisplayName, Direction, Action, Protocol, Enabled
            $fwRules | ConvertTo-Json |
                Out-File -FilePath (Join-Path $dfirDir "event3_firewall_rules.json") -Encoding utf8
            $summary.dfir_artifacts += "event3_firewall_rules.json"
            Log-Detail "DFIR: Saved event3_firewall_rules.json"
        } catch {
            Log-Detail "DFIR: Event3 firewall rules failed: $($_.Exception.Message)"
        }

        try {
            $routes = Get-NetRoute -ErrorAction SilentlyContinue |
                Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias, AddressFamily
            $routes | ConvertTo-Json |
                Out-File -FilePath (Join-Path $dfirDir "event3_routing_table.json") -Encoding utf8
            $summary.dfir_artifacts += "event3_routing_table.json"
        } catch {}

        # เก็บ ARP cache
        try {
            $arpCache = Get-NetNeighbor -ErrorAction SilentlyContinue |
                Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
            $arpCache | ConvertTo-Json |
                Out-File -FilePath (Join-Path $dfirDir "event3_arp_cache.json") -Encoding utf8
            $summary.dfir_artifacts += "event3_arp_cache.json"
        } catch {}
    }

    # Event 6: Driver - เก็บ loaded drivers + services
    if ($EventType -eq "Event6") {
        try {
            $drivers = Get-CimInstance Win32_SystemDriver |
                Select-Object Name, DisplayName, PathName, State, StartMode, Description
            $drivers | ConvertTo-Json |
                Out-File -FilePath (Join-Path $dfirDir "event6_loaded_drivers.json") -Encoding utf8
            $summary.dfir_artifacts += "event6_loaded_drivers.json"
            Log-Detail "DFIR: Saved event6_loaded_drivers.json"
        } catch {
            Log-Detail "DFIR: Event6 drivers failed: $($_.Exception.Message)"
        }

        try {
            $services = Get-Service | Select-Object Name, DisplayName, Status, StartType
            $services | ConvertTo-Json |
                Out-File -FilePath (Join-Path $dfirDir "event6_services.json") -Encoding utf8
            $summary.dfir_artifacts += "event6_services.json"
        } catch {}
    }

    # Event 7: DLL - เก็บ modules ที่โหลดใน process
    if ($EventType -eq "Event7" -and $ProcessImage) {
        try {
            $loadedProc = Get-CimInstance Win32_Process |
                Where-Object { $_.ExecutablePath -eq $ProcessImage } |
                Select-Object -First 1
            if ($loadedProc) {
                $modules = (Get-Process -Id $loadedProc.ProcessId -ErrorAction SilentlyContinue).Modules |
                    Select-Object ModuleName, FileName, @{N='Size';E={$_.ModuleMemorySize}}, Description, FileVersion
                $modules | ConvertTo-Json |
                    Out-File -FilePath (Join-Path $dfirDir "event7_loaded_modules.json") -Encoding utf8
                $summary.dfir_artifacts += "event7_loaded_modules.json"
                Log-Detail "DFIR: Saved event7_loaded_modules.json"
            }
        } catch {
            Log-Detail "DFIR: Event7 modules failed: $($_.Exception.Message)"
        }
    }

    # Event 15 / Event 29: ADS Streams
    if ($EventType -in @("Event15","Event29") -and $TargetFile -and (Test-Path $TargetFile)) {
        try {
            $streams = Get-Item $TargetFile -Stream * -ErrorAction SilentlyContinue |
                Select-Object Stream, Length
            $streams | ConvertTo-Json |
                Out-File -FilePath (Join-Path $dfirDir "${EventType}_ads_streams.json") -Encoding utf8
            $summary.dfir_artifacts += "${EventType}_ads_streams.json"
            Log-Detail "DFIR: Saved ${EventType}_ads_streams.json"
        } catch {
            Log-Detail "DFIR: ADS streams failed: $($_.Exception.Message)"
        }
    }

    # Event 22: DNS - เก็บ hosts file + DNS server config
    if ($EventType -eq "Event22") {
        try {
            $hostsPath    = "C:\Windows\System32\drivers\etc\hosts"
            $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
            $hostsContent | Out-File -FilePath (Join-Path $dfirDir "event22_hosts_file.txt") -Encoding utf8
            $summary.dfir_artifacts += "event22_hosts_file.txt"

            $dnsServers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
                Select-Object InterfaceAlias, AddressFamily, ServerAddresses
            $dnsServers | ConvertTo-Json |
                Out-File -FilePath (Join-Path $dfirDir "event22_dns_servers.json") -Encoding utf8
            $summary.dfir_artifacts += "event22_dns_servers.json"
            Log-Detail "DFIR: Saved Event22 DNS artifacts"
        } catch {
            Log-Detail "DFIR: Event22 DNS artifacts failed: $($_.Exception.Message)"
        }
    }

    # Event 26: ดึงข้อมูลจาก Sysmon archive ถ้ายังมี
    if ($EventType -eq "Event26" -and $IOCValue) {
        try {
            $sysmonArchiveDirs = @("C:\Sysmon","C:\Windows\Sysmon","C:\ProgramData\Sysmon")
            foreach ($archDir in $sysmonArchiveDirs) {
                $archivedPath = Join-Path $archDir $IOCValue
                if (Test-Path $archivedPath) {
                    $copyDest = Join-Path $dfirDir "event26_sysmon_archive_COPY"
                    Copy-Item $archivedPath -Destination $copyDest -Force
                    $summary.dfir_artifacts += "event26_sysmon_archive_COPY"
                    Log-Detail "DFIR: Copied Sysmon archive: $archivedPath"
                    $summary.actions_taken += "Copied Sysmon archive: $archivedPath"
                    break
                }
            }
        } catch {
            Log-Detail "DFIR: Event26 Sysmon archive copy failed: $($_.Exception.Message)"
        }
    }

    # ---- 9. AUTORUN / PERSISTENCE CHECK ----
    try {
        $regRunKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        $autoruns = @{}
        foreach ($key in $regRunKeys) {
            try {
                $vals = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($vals) {
                    $autoruns[$key] = $vals | ConvertTo-Json -Depth 3 -ErrorAction SilentlyContinue
                }
            } catch {}
        }

        # Scheduled tasks
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Select-Object TaskName, TaskPath, State,
                @{N='Actions';E={$_.Actions | ConvertTo-Json -Compress -Depth 3}}

        @{ registry_autoruns = $autoruns; scheduled_tasks = @($tasks) } |
            ConvertTo-Json -Depth 10 |
            Out-File -FilePath (Join-Path $dfirDir "persistence_autoruns.json") -Encoding utf8
        $summary.dfir_artifacts += "persistence_autoruns.json"
        Log-Detail "DFIR: Saved persistence_autoruns.json"
    } catch {
        Log-Detail "DFIR: persistence_autoruns.json failed: $($_.Exception.Message)"
    }

    # ---- 10. Windows Event Log (Security + System + Sysmon) - 30 นาทีย้อนหลัง ----
    try {
        $since    = (Get-Date).AddMinutes(-30)
        $evtLogs  = @{}

        foreach ($logName in @("Security","System","Microsoft-Windows-Sysmon/Operational")) {
            try {
                $events = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue |
                    Where-Object { $_.TimeCreated -ge $since } |
                    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
                    Select-Object -First 500   # cap ไว้ที่ 500 events ต่อ log

                $evtLogs[$logName] = @($events)
            } catch {}
        }

        $evtLogs | ConvertTo-Json -Depth 8 |
            Out-File -FilePath (Join-Path $dfirDir "windows_events_30min.json") -Encoding utf8
        $summary.dfir_artifacts += "windows_events_30min.json"
        Log-Detail "DFIR: Saved windows_events_30min.json"
    } catch {
        Log-Detail "DFIR: windows_events_30min.json failed: $($_.Exception.Message)"
    }

    # ---- 11. บันทึก Summary ----
    try {
        $summary | ConvertTo-Json -Depth 10 |
            Out-File -FilePath (Join-Path $dfirDir "dfir_summary.json") -Encoding utf8
        Log-Detail "DFIR: Saved dfir_summary.json → $dfirDir"
    } catch {
        Log-Detail "DFIR: dfir_summary.json failed: $($_.Exception.Message)"
    }

    Log-Detail "DFIR: Collection complete. Artifacts saved to: $dfirDir"
    return $dfirDir
}

Log-Detail "=== AR SCRIPT STARTED (PowerShell) ==="

# Ensure DFIR root directory exists
if (-not (Test-Path $dfirRoot)) {
    try {
        New-Item -ItemType Directory -Path $dfirRoot -Force | Out-Null
        Log-Detail "Created DFIR root: $dfirRoot"
    } catch {
        Log-Detail "WARNING: Could not create DFIR root: $($_.Exception.Message)"
    }
}

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
# 3. Extract IOC
# =========================
# CDB List มี 2 format ต่างกัน:
#   misp_sha256_sysmonuse → "SHA256=ABCDEF..." uppercase มี prefix  (Sysmon rules 110030-110036)
#   misp_sha256           → "6a973119..."     lowercase ไม่มี prefix (FIM/Syscheck rules 110002-110005)
#
# script นี้ normalize ทุก hash เป็น uppercase hex ล้วน (ไม่มี prefix)
# เพื่อ compare กับ Get-FileHash ที่คืน uppercase hex เสมอ
# =========================
$IOCvalue = $null
$IOCtype  = $null
$IOCmode  = $null

$eventID    = $alert.data.win.system.eventID
$hashes_val = $alert.data.win.eventdata.hashes   # Event 1,6,7,26,29 → "MD5=xx,SHA256=XX..."
$hash_val   = $alert.data.win.eventdata.hash     # Event 15           → "MD5=xx,SHA256=XX..."

# -----------------------------------------------------------
# Mode A: Sysmon hash events (Rules 110030-110036)
# CDB: misp_sha256_sysmonuse → value ใน alert field เป็น "SHA256=UPPERCASE"
# ดึง SHA256 hex ออกจาก field แล้ว normalize uppercase
# Priority สูงสุด: ถ้า eventID เป็น Sysmon hash event ให้ใช้ field นี้ก่อนเสมอ
# -----------------------------------------------------------
$sysmonHashEvents = @("1","6","7","26","29")
$hashField = $null

if ($eventID -in $sysmonHashEvents -and $hashes_val) {
    $hashField     = $hashes_val
    $hashFieldName = "hashes"
} elseif ($eventID -eq "15" -and $hash_val) {
    $hashField     = $hash_val
    $hashFieldName = "hash"
} elseif ($hashes_val) {
    # fallback: unknown eventID แต่มี hashes field
    $hashField     = $hashes_val
    $hashFieldName = "hashes (fallback)"
} elseif ($hash_val) {
    $hashField     = $hash_val
    $hashFieldName = "hash (fallback)"
}

if ($hashField -and $hashField -match "SHA256=([A-Fa-f0-9]{64})") {
    $IOCvalue = $matches[1].ToUpper()
    $IOCtype  = "sha256"
    $IOCmode  = "Sysmon"
    Log-Detail "Mode A: Sysmon hash (EventID=$eventID field=$hashFieldName) → IOC=$IOCvalue"
}

# -----------------------------------------------------------
# Mode B: FIM / Syscheck (Rules 110002-110005)
# CDB: misp_sha256 → value เป็น lowercase hex ล้วน ไม่มี prefix
# alert.syscheck.sha256_after คืน lowercase hex ตรงๆ
# → ToUpper() เพื่อ normalize
# -----------------------------------------------------------
if (-not $IOCvalue -and $alert.syscheck.sha256_after) {
    $IOCvalue = ($alert.syscheck.sha256_after).ToUpper()
    $IOCtype  = "sha256"
    $IOCmode  = "FIM"
    Log-Detail "Mode B: FIM/Syscheck → IOC=$IOCvalue"
}

# -----------------------------------------------------------
# Mode D: Network / DNS (Event 3, 22) — no hash, IOC คือ IP / Domain
# -----------------------------------------------------------
if (-not $IOCvalue) {
    if ($eventID -eq "3" -and $alert.data.win.eventdata.destinationIp) {
        $IOCvalue = $alert.data.win.eventdata.destinationIp
        $IOCtype  = "ip"
        $IOCmode  = "Sysmon-Event3"
        Log-Detail "Mode D: Event3 → IP=$IOCvalue"
    } elseif ($eventID -eq "22" -and $alert.data.win.eventdata.queryName) {
        $IOCvalue = $alert.data.win.eventdata.queryName
        $IOCtype  = "domain"
        $IOCmode  = "Sysmon-Event22"
        Log-Detail "Mode D: Event22 → Domain=$IOCvalue"
    }
}

if (-not $IOCvalue) {
    Log-Detail "No IOC found in any mode - EXIT"
    exit 0
}

Log-Detail "IOC FINAL: value=$IOCvalue type=$IOCtype mode=$IOCmode"

# =========================
# 4. Extract Fields
# =========================
$agentName      = $alert.agent.name
# $imagePathGlobal = process image จาก alert (ใช้เป็น default เท่านั้น)
# แต่ละ event block จะ re-extract field ของตัวเองเพื่อหลีกเลี่ยง collision
$imagePathGlobal = $alert.data.win.eventdata.image
$processId       = $alert.data.win.eventdata.processId
$parentImage     = $alert.data.win.eventdata.parentImage
$commandLine     = $alert.data.win.eventdata.commandLine
$userName        = $alert.data.win.eventdata.user
$filePath        = $alert.syscheck.path
$destIp          = $alert.data.win.eventdata.destinationIp
$destPort        = $alert.data.win.eventdata.destinationPort

Log-Detail "Sysmon Image (global): $imagePathGlobal"
Log-Detail "Syscheck Path: $filePath"
Log-Detail "Agent: $agentName"

# =========================
# 5. FILE RESPONSE (Sysmon Generic - image field)
# ใช้เฉพาะกรณีที่ eventID ไม่ตรงกับ block ด้านล่าง (safety fallback)
# ไม่ทำงานถ้า eventID เป็น 1,6,7,15,26,29 เพราะมี block เฉพาะอยู่แล้ว
# =========================
$handledBySpecificBlock = $eventID -in @("1","6","7","15","26","29")

if ($IOCtype -eq "sha256" -and $imagePathGlobal -and -not $handledBySpecificBlock) {

    if (Test-Path $imagePathGlobal) {
        try {
            $fileHash = (Get-FileHash $imagePathGlobal -Algorithm SHA256).Hash.ToUpper()

            if ($fileHash -eq $IOCvalue) {
                Log-Detail "Sysmon Generic HASH MATCH (EventID=$eventID) -> action"

                Invoke-DFIRCollection -EventType "Sysmon_Generic_EventID${eventID}" `
                    -IOCValue $IOCvalue -IOCType $IOCtype `
                    -TargetFile $imagePathGlobal -ProcessImage $imagePathGlobal `
                    -ProcessId $processId -AgentName $agentName `
                    -RawAlert $alert | Out-Null

                if ($processId) {
                    try {
                        Stop-Process -Id $processId -Force
                        Log-Detail "Killed PID: $processId"
                    } catch {
                        Log-Detail "Kill failed: $($_.Exception.Message)"
                    }
                }

                try {
                    Remove-Item $imagePathGlobal -Force
                    Log-Detail "Deleted file: $imagePathGlobal"
                } catch {
                    Log-Detail "Delete failed: $($_.Exception.Message)"
                }
            } else {
                Log-Detail "Sysmon Generic: hash mismatch (file=$fileHash, IOC=$IOCvalue)"
            }
        } catch {
            Log-Detail "Sysmon Generic handling error: $($_.Exception.Message)"
        }
    }
}

# =========================
# 5b. PROCESS RESPONSE (Sysmon Event 1)
# =========================
if ($IOCtype -eq "sha256" -and $eventID -eq "1") {
    $ev1_imagePath = $alert.data.win.eventdata.image
    $ev1_processId = $alert.data.win.eventdata.processId

    Log-Detail "Event 1: Malicious process detected - $ev1_imagePath (PID=$ev1_processId)"

    # Verify hash ก่อน action เสมอ (ป้องกัน false positive)
    $ev1_hashMatch = $false
    if ($ev1_imagePath -and (Test-Path $ev1_imagePath)) {
        try {
            $ev1_fileHash = (Get-FileHash $ev1_imagePath -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event 1: file hash=$ev1_fileHash, IOC=$IOCvalue"
            if ($ev1_fileHash -eq $IOCvalue) { $ev1_hashMatch = $true }
            else { Log-Detail "Event 1: hash mismatch - no action" }
        } catch {
            Log-Detail "Event 1: hash check failed: $($_.Exception.Message)"
        }
    } else {
        # ไฟล์อาจหายไปแล้ว (process ถูก inject / packed) - ยังทำ DFIR แต่ skip delete
        Log-Detail "Event 1: image path not found on disk: $ev1_imagePath"
    }

    # --- DFIR: เก็บก่อน kill ---
    Invoke-DFIRCollection -EventType "Event1" `
        -IOCValue $IOCvalue -IOCType $IOCtype `
        -ProcessImage $ev1_imagePath -ProcessId $ev1_processId `
        -ParentImage $parentImage -CommandLine $commandLine `
        -User $userName -AgentName $agentName `
        -RawAlert $alert | Out-Null

    if ($ev1_hashMatch) {
        if ($ev1_processId) {
            try {
                Stop-Process -Id $ev1_processId -Force
                Log-Detail "Killed PID: $ev1_processId"
            } catch {
                Log-Detail "Kill PID failed: $($_.Exception.Message)"
            }
        }

        if ($ev1_imagePath) {
            try {
                $procs = Get-CimInstance Win32_Process | Where-Object {
                    $_.ExecutablePath -eq $ev1_imagePath
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

        if ($ev1_imagePath -and (Test-Path $ev1_imagePath)) {
            try {
                Remove-Item $ev1_imagePath -Force
                Log-Detail "Deleted executable: $ev1_imagePath"
            } catch {
                Log-Detail "Delete failed: $($_.Exception.Message)"
            }
        }
    }
}

# =========================
# 5c. DRIVER RESPONSE (Sysmon Event 6)
# =========================
if ($IOCtype -eq "sha256" -and $eventID -eq "6") {
    $ev6_driverPath = $alert.data.win.eventdata.imageLoaded

    Log-Detail "Event 6: Malicious driver detected - $ev6_driverPath"

    # --- DFIR: เก็บก่อน ---
    Invoke-DFIRCollection -EventType "Event6" `
        -IOCValue $IOCvalue -IOCType $IOCtype `
        -TargetFile $ev6_driverPath -AgentName $agentName `
        -RawAlert $alert | Out-Null

    if ($ev6_driverPath -and (Test-Path $ev6_driverPath)) {
        # Verify hash ก่อน
        try {
            $ev6_fileHash = (Get-FileHash $ev6_driverPath -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event 6: file hash=$ev6_fileHash, IOC=$IOCvalue"
        } catch {
            $ev6_fileHash = ""
            Log-Detail "Event 6: hash check failed: $($_.Exception.Message)"
        }

        if ($ev6_fileHash -eq $IOCvalue) {
            try {
                $code = @"
using System;
using System.Runtime.InteropServices;
public class FileHelperDrv {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName,
        string lpNewFileName, int dwFlags);
    public const int MOVEFILE_DELAY_UNTIL_REBOOT = 4;
}
"@
                Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
                $result = [FileHelperDrv]::MoveFileEx($ev6_driverPath, $null,
                    [FileHelperDrv]::MOVEFILE_DELAY_UNTIL_REBOOT)

                if ($result) {
                    Log-Detail "Scheduled driver delete on reboot: $ev6_driverPath"
                } else {
                    Log-Detail "MoveFileEx failed (Event 6)"
                }
            } catch {
                Log-Detail "Driver delete error: $($_.Exception.Message)"
            }

            try {
                $ev6_driverName = [System.IO.Path]::GetFileNameWithoutExtension($ev6_driverPath)
                $svc = Get-Service -Name $ev6_driverName -ErrorAction SilentlyContinue
                if ($svc) {
                    Stop-Service -Name $ev6_driverName -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $ev6_driverName -StartupType Disabled
                    Log-Detail "Disabled driver service: $ev6_driverName"
                }
            } catch {
                Log-Detail "Service disable error: $($_.Exception.Message)"
            }
        } else {
            Log-Detail "Event 6: hash mismatch - no action"
        }
    }
}

# =========================
# 5d. DLL RESPONSE (Sysmon Event 7)
# =========================
if ($IOCtype -eq "sha256" -and $eventID -eq "7") {
    $ev7_dllPath   = $alert.data.win.eventdata.imageLoaded
    $ev7_procImage = $alert.data.win.eventdata.image

    Log-Detail "Event 7: Malicious DLL detected - $ev7_dllPath"
    Log-Detail "Loaded by process: $ev7_procImage"

    # Verify hash ก่อน
    $ev7_hashMatch = $false
    if ($ev7_dllPath -and (Test-Path $ev7_dllPath)) {
        try {
            $ev7_fileHash = (Get-FileHash $ev7_dllPath -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event 7: file hash=$ev7_fileHash, IOC=$IOCvalue"
            if ($ev7_fileHash -eq $IOCvalue) { $ev7_hashMatch = $true }
            else { Log-Detail "Event 7: hash mismatch - no action" }
        } catch {
            Log-Detail "Event 7: hash check failed: $($_.Exception.Message)"
        }
    } else {
        Log-Detail "Event 7: DLL path not found: $ev7_dllPath"
    }

    # --- DFIR: เก็บก่อน kill ---
    Invoke-DFIRCollection -EventType "Event7" `
        -IOCValue $IOCvalue -IOCType $IOCtype `
        -TargetFile $ev7_dllPath -ProcessImage $ev7_procImage `
        -AgentName $agentName -RawAlert $alert | Out-Null

    if ($ev7_hashMatch) {
        try {
            $procs = Get-CimInstance Win32_Process | Where-Object {
                $_.ExecutablePath -eq $ev7_procImage
            }
            foreach ($p in $procs) {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                Log-Detail "Killed process PID: $($p.ProcessId) ($($p.Name))"
            }
        } catch {
            Log-Detail "Kill process failed: $($_.Exception.Message)"
        }

        Start-Sleep -Seconds 2

        if ($ev7_dllPath -and (Test-Path $ev7_dllPath)) {
            try {
                Remove-Item $ev7_dllPath -Force
                Log-Detail "Deleted DLL: $ev7_dllPath"
            } catch {
                try {
                    $code7 = @"
using System;
using System.Runtime.InteropServices;
public class FileHelperDll {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName,
        string lpNewFileName, int dwFlags);
    public const int MOVEFILE_DELAY_UNTIL_REBOOT = 4;
}
"@
                    Add-Type -TypeDefinition $code7 -ErrorAction SilentlyContinue
                    $result = [FileHelperDll]::MoveFileEx($ev7_dllPath, $null,
                        [FileHelperDll]::MOVEFILE_DELAY_UNTIL_REBOOT)
                    if ($result) {
                        Log-Detail "Scheduled DLL delete on reboot: $ev7_dllPath"
                    } else {
                        Log-Detail "MoveFileEx failed (Event 7)"
                    }
                } catch {
                    Log-Detail "Schedule delete failed (Event 7): $($_.Exception.Message)"
                }
            }
        }
    }
}

# =========================
# 5e. FILE RESPONSE (Sysmon Event 15 - FileCreateStreamHash)
# Field ที่ใช้: targetFilename + hash (singular, ไม่ใช่ hashes)
# =========================
if ($IOCtype -eq "sha256" -and $eventID -eq "15") {

    $ev15_targetFile  = $alert.data.win.eventdata.targetFilename
    $ev15_imageSource = $alert.data.win.eventdata.image   # process ที่เขียน stream

    Log-Detail "Event 15: targetFilename=$ev15_targetFile"
    Log-Detail "Event 15: written by=$ev15_imageSource"

    if ($ev15_targetFile -and (Test-Path $ev15_targetFile)) {
        try {
            $ev15_fileHash = (Get-FileHash $ev15_targetFile -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event 15: file hash=$ev15_fileHash"
            Log-Detail "Event 15: IOC hash= $IOCvalue"

            if ($ev15_fileHash -eq $IOCvalue) {
                Log-Detail "Event 15: HASH MATCH -> kill processes then delete"

                # --- DFIR: เก็บก่อนลบ ---
                Invoke-DFIRCollection -EventType "Event15" `
                    -IOCValue $IOCvalue -IOCType $IOCtype `
                    -TargetFile $ev15_targetFile -ProcessImage $ev15_imageSource `
                    -AgentName $agentName -RawAlert $alert | Out-Null

                # Kill process ที่เปิดไฟล์นี้ผ่าน CommandLine
                try {
                    $processes = Get-CimInstance Win32_Process | Where-Object {
                        $_.CommandLine -like "*$ev15_targetFile*"
                    }
                    foreach ($proc in $processes) {
                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                        Log-Detail "Event 15: Killed PID $($proc.ProcessId) ($($proc.Name))"
                    }
                } catch {
                    Log-Detail "Event 15: Kill by CommandLine failed: $($_.Exception.Message)"
                }

                # ใช้ handle64.exe ถ้ามี
                $handleExe = "C:\Tools\handle64.exe"
                if (Test-Path $handleExe) {
                    try {
                        $handleOutput = & $handleExe -accepteula -nobanner "$ev15_targetFile" 2>&1
                        foreach ($line in $handleOutput) {
                            if ($line -match "pid: (\d+)") {
                                $pidProcess = $matches[1]
                                Stop-Process -Id $pidProcess -Force -ErrorAction SilentlyContinue
                                Log-Detail "Event 15: Killed handle PID: $pidProcess"
                            }
                        }
                    } catch {
                        Log-Detail "Event 15: handle64 failed: $($_.Exception.Message)"
                    }
                }

                Start-Sleep -Seconds 2

                # ลบไฟล์
                try {
                    Remove-Item $ev15_targetFile -Force
                    Log-Detail "Event 15: Deleted: $ev15_targetFile"
                } catch {
                    # Fallback 1: cmd del
                    $ev15_deleted = $false
                    try {
                        $proc = Start-Process "cmd.exe" -ArgumentList "/c del /f /q `"$ev15_targetFile`"" `
                            -WindowStyle Hidden -Wait -PassThru
                        if (-not (Test-Path $ev15_targetFile)) {
                            $ev15_deleted = $true
                            Log-Detail "Event 15: Deleted via cmd: $ev15_targetFile"
                        }
                    } catch {}

                    # Fallback 2: MoveFileEx - schedule delete on reboot
                    if (-not $ev15_deleted) {
                        try {
                            $code15 = @"
using System;
using System.Runtime.InteropServices;
public class FileHelper15 {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName,
        string lpNewFileName, int dwFlags);
    public const int MOVEFILE_DELAY_UNTIL_REBOOT = 4;
}
"@
                            Add-Type -TypeDefinition $code15 -ErrorAction SilentlyContinue
                            $result = [FileHelper15]::MoveFileEx($ev15_targetFile, $null,
                                [FileHelper15]::MOVEFILE_DELAY_UNTIL_REBOOT)
                            if ($result) {
                                Log-Detail "Event 15: Scheduled delete on reboot: $ev15_targetFile"
                            } else {
                                Log-Detail "Event 15: MoveFileEx also failed"
                            }
                        } catch {
                            Log-Detail "Event 15: All delete methods failed: $($_.Exception.Message)"
                        }
                    }
                }

            } else {
                Log-Detail "Event 15: Hash mismatch (file=$ev15_fileHash, IOC=$IOCvalue) - no action"
            }
        } catch {
            Log-Detail "Event 15: Error: $($_.Exception.Message)"
        }
    } else {
        Log-Detail "Event 15: targetFile not found: $ev15_targetFile"
    }
}

# =========================
# 5f. FILE RESPONSE (Sysmon Event 26)
# =========================
if ($IOCtype -eq "sha256" -and $eventID -eq "26") {

    $ev26_targetFile  = $alert.data.win.eventdata.targetFilename
    $ev26_parentImage = $alert.data.win.eventdata.image
    Log-Detail "Event 26 (File Delete Detected): $ev26_targetFile"

    # --- DFIR: เก็บก่อนทุก action ---
    Invoke-DFIRCollection -EventType "Event26" `
        -IOCValue $IOCvalue -IOCType $IOCtype `
        -TargetFile $ev26_targetFile -ProcessImage $ev26_parentImage `
        -AgentName $agentName -RawAlert $alert | Out-Null

    if ($ev26_targetFile -and (Test-Path $ev26_targetFile)) {
        try {
            $ev26_fileHash = (Get-FileHash $ev26_targetFile -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event 26: file hash=$ev26_fileHash, IOC=$IOCvalue"

            if ($ev26_fileHash -eq $IOCvalue) {
                Log-Detail "Event 26: HASH MATCH - original file still exists -> delete"
                try {
                    Remove-Item $ev26_targetFile -Force
                    Log-Detail "Event 26: Deleted original file: $ev26_targetFile"
                } catch {
                    Log-Detail "Event 26: Delete failed: $($_.Exception.Message)"
                }
            } else {
                Log-Detail "Event 26: Hash mismatch - no action on original"
            }
        } catch {
            Log-Detail "Event 26: hash check error: $($_.Exception.Message)"
        }
    } else {
        Log-Detail "Event 26: Original file already gone - checking Sysmon archive"
    }

    $sysmonArchiveDirs = @("C:\Sysmon","C:\Windows\Sysmon","C:\ProgramData\Sysmon")
    foreach ($archiveDir in $sysmonArchiveDirs) {
        if (Test-Path $archiveDir) {
            $archivedFile = Join-Path $archiveDir $IOCvalue
            if (Test-Path $archivedFile) {
                try {
                    Remove-Item $archivedFile -Force
                    Log-Detail "Event 26: Deleted Sysmon archive copy: $archivedFile"
                } catch {
                    Log-Detail "Event 26: Delete archive failed: $($_.Exception.Message)"
                }
            } else {
                Log-Detail "Event 26: No archive copy found at: $archivedFile"
            }
        }
    }

    if ($ev26_parentImage) {
        Log-Detail "Event 26: triggered by process: $ev26_parentImage"
        Log-Detail "NOTE: Review process '$ev26_parentImage' manually if suspicious"
    }
}

# =========================
# 5g. FILE RESPONSE (Sysmon Event 29)
# =========================
if ($IOCtype -eq "sha256" -and $eventID -eq "29") {

    $ev29_targetFile  = $alert.data.win.eventdata.targetFilename
    $ev29_parentImage = $alert.data.win.eventdata.image
    Log-Detail "Event 29 (File Executable Detected): $ev29_targetFile"

    if ($ev29_targetFile -and (Test-Path $ev29_targetFile)) {
        try {
            $ev29_fileHash = (Get-FileHash $ev29_targetFile -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event 29: file hash=$ev29_fileHash, IOC=$IOCvalue"

            if ($ev29_fileHash -eq $IOCvalue) {
                Log-Detail "Event 29: HASH MATCH -> kill parent process then delete"

                # --- DFIR: เก็บก่อน kill ---
                Invoke-DFIRCollection -EventType "Event29" `
                    -IOCValue $IOCvalue -IOCType $IOCtype `
                    -TargetFile $ev29_targetFile -ProcessImage $ev29_parentImage `
                    -AgentName $agentName -RawAlert $alert | Out-Null

                if ($ev29_parentImage) {
                    try {
                        $procs = Get-CimInstance Win32_Process | Where-Object {
                            $_.ExecutablePath -eq $ev29_parentImage
                        }
                        foreach ($p in $procs) {
                            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                            Log-Detail "Event 29: Killed parent PID $($p.ProcessId) ($ev29_parentImage)"
                        }
                    } catch {
                        Log-Detail "Event 29: Kill parent failed: $($_.Exception.Message)"
                    }
                }

                try {
                    $procs2 = Get-CimInstance Win32_Process | Where-Object {
                        $_.ExecutablePath -eq $ev29_targetFile
                    }
                    foreach ($p in $procs2) {
                        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                        Log-Detail "Event 29: Killed running target PID $($p.ProcessId)"
                    }
                } catch {
                    Log-Detail "Event 29: Kill target failed: $($_.Exception.Message)"
                }

                Start-Sleep -Seconds 2

                try {
                    Remove-Item $ev29_targetFile -Force
                    Log-Detail "Event 29: Deleted: $ev29_targetFile"
                } catch {
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
                        $result = [FileHelper29]::MoveFileEx($ev29_targetFile, $null,
                            [FileHelper29]::MOVEFILE_DELAY_UNTIL_REBOOT)
                        if ($result) {
                            Log-Detail "Event 29: Scheduled delete on reboot: $ev29_targetFile"
                        } else {
                            Log-Detail "Event 29: MoveFileEx failed"
                        }
                    } catch {
                        Log-Detail "Event 29: Schedule delete failed: $($_.Exception.Message)"
                    }
                }

            } else {
                Log-Detail "Event 29: Hash mismatch (file=$ev29_fileHash, IOC=$IOCvalue) - no action"
            }
        } catch {
            Log-Detail "Event 29: handling error: $($_.Exception.Message)"
        }
    } else {
        Log-Detail "Event 29: targetFile not found: $ev29_targetFile"
    }
}

# =========================
# 6. FILE RESPONSE (FIM)
# =========================
if ($IOCtype -eq "sha256" -and $filePath) {

    if (Test-Path $filePath) {
        try {
            $fileHash = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToUpper()

            if ($fileHash -eq $IOCvalue) {
                Log-Detail "FIM HASH MATCH (file=$fileHash) -> kill processes then delete"

                # --- DFIR: เก็บก่อนลบ ---
                Invoke-DFIRCollection -EventType "FIM" `
                    -IOCValue $IOCvalue -IOCType $IOCtype `
                    -TargetFile $filePath -AgentName $agentName `
                    -RawAlert $alert | Out-Null

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

                Start-Sleep -Seconds 2

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
                Log-Detail "FIM hash mismatch (file=$fileHash, IOC=$IOCvalue) - no action"
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
        # --- DFIR: เก็บ network context ---
        Invoke-DFIRCollection -EventType "Event3" `
            -IOCValue $ip -IOCType "ip" `
            -ProcessImage $winEventdata.image `
            -DestinationIp $ip -DestinationPort $winEventdata.destinationPort `
            -AgentName $agentName -RawAlert $alert | Out-Null

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

    $domain    = $winEventdata.queryName
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"

    if ($domain) {
        # --- DFIR: เก็บ DNS context ---
        Invoke-DFIRCollection -EventType "Event22" `
            -IOCValue $domain -IOCType "domain" `
            -ProcessImage $winEventdata.image `
            -Domain $domain -AgentName $agentName `
            -RawAlert $alert | Out-Null

        if (-not (Select-String $hostsPath $domain -Quiet)) {
            Add-Content $hostsPath "127.0.0.1`t$domain"
            Log-Detail "Blocked domain: $domain"
        }
    }
}

# =========================
# END
# =========================
Log-Detail "=== AR SCRIPT ENDED ==="
exit 0
