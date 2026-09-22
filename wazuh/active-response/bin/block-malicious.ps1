################################
## Wazuh Active Response (FINAL) - MISP + Sysmon(1,3,6,7,15,22,26,29) + FIM
## Watchdog-aware containment (signature-gated) + DFIR collection (background job)
## v36 5aug2569: Authenticode gate + BYOVD carve-out + takeown/sdset + Confirm-IocFile
################################

$logFile    = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$dfirScript = "C:\install-sysmon\Invoke-DFIRCollection.ps1"

function Log-Detail {
    param([string]$msg)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $msg" | Out-File -FilePath $logFile -Append -Encoding utf8
}

function Normalize-AlertPath {
    # 22ก.ย.69: path ที่มากับ alert ของ Wazuh มี backslash ซ้อน (C:\\Windows\\..)
    # ทำให้การเทียบ StartsWith() ทุกจุดไม่ติด (DFIR loop guard / protected path)
    # (?<!^) กัน UNC path \\server\share ไม่ให้ถูกยุบ
    param([string]$p)
    if ([string]::IsNullOrWhiteSpace($p)) { return "" }
    return ($p -replace '(?<!^)\\{2,}', '\')
}

function Log-ARJson {
    # 22ก.ย.69 - เขียน "บรรทัดเดียว" รูปแบบมาตรฐาน Wazuh เพื่อให้ decoder ar_log_json อ่านได้
    # ทำให้ alert ฝั่ง SIEM เห็นบริบทครบ (กฎไหน เครื่องไหน ไฟล์อะไร ค่าแฮชอะไร)
    # เทียบเท่าที่ kong-block ได้จาก execd -- custom script ต้องเขียนเอง
    param($Cmd, $Alert, $Program)
    try {
        $cmdStr = "add"
        if ($Cmd) { $cmdStr = "$Cmd" }
        # ชื่อโปรแกรมต้องมาจากที่ execd ส่งมา (= <executable> ใน ossec.conf = action-script.bat)
        # ไม่ hardcode เป็น block-malicious.ps1 เพราะ AR command ที่ประกาศไว้คือ action-script
        $prog = "active-response/bin/action-script.bat"
        if ($Program) { $prog = "$Program" }
        $ev = $Alert.data.win.eventdata
        $ctx = [ordered]@{
            version    = 1
            origin     = [ordered]@{ name = ""; module = "wazuh-execd" }
            command    = $cmdStr
            parameters = [ordered]@{
                extra_args = @()
                program    = $prog
                alert      = [ordered]@{
                    rule     = [ordered]@{
                        id          = "$($Alert.rule.id)"
                        level       = "$($Alert.rule.level)"
                        description = "$($Alert.rule.description)"
                    }
                    agent    = [ordered]@{
                        id   = "$($Alert.agent.id)"
                        name = "$($Alert.agent.name)"
                    }
                    data     = [ordered]@{ win = [ordered]@{ eventdata = [ordered]@{
                        targetFilename = "$($ev.targetFilename)"
                        image          = "$($ev.image)"
                        imageLoaded    = "$($ev.imageLoaded)"
                        hashes         = "$($ev.hashes)"
                        hash           = "$($ev.hash)"
                        queryName      = "$($ev.queryName)"
                    } } }
                    syscheck = [ordered]@{
                        path         = "$($Alert.syscheck.path)"
                        sha256_after = "$($Alert.syscheck.sha256_after)"
                    }
                }
            }
        }
        $json = $ctx | ConvertTo-Json -Compress -Depth 9
        $json = $json -replace "`r", " " -replace "`n", " "
        $ts   = Get-Date -Format 'yyyy/MM/dd HH:mm:ss'
        ($ts + " " + $prog + ": " + $json) |
            Out-File -FilePath $logFile -Append -Encoding utf8
    } catch {
        Log-Detail "Log-ARJson failed: $($_.Exception.Message)"
    }
}

function Start-DFIRBackground {
    param(
        [string]$EventType,
        [string]$IOCValue,
        [string]$IOCType,
        [string]$AlertJson,
        [string]$TargetFile    = "",
        [string]$ProcessImage  = "",
        [string]$ProcessId     = "",
        [string]$ParentImage   = "",
        [string]$DestinationIp = "",
        [string]$Domain        = "",
        [string]$AgentName     = ""
    )
    try {
        $tmpDir  = "C:\install-sysmon\dfir-tmp"
        if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null }
        $ts      = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
        $tmpFile = Join-Path $tmpDir "alert_${ts}.json"
        $AlertJson | Out-File -FilePath $tmpFile -Encoding utf8 -Force

        # 22ก.ย.69 FIX (DFIR race): DFIR รันเป็น background job แต่ Invoke-Containment
        # ลบไฟล์ทันทีใน foreground -> DFIR มาถึงตอน Test-Path=false จึงไม่ได้หลักฐานตัวจริง
        # แก้: สำเนาไฟล์เป้าหมาย "แบบ synchronous" ไว้ก่อน (ไฟล์เดียว เร็ว)
        # ส่วนงานช้า (process list/network/sysmon) ยังเป็น background เหมือนเดิม
        $preserved = ""
        try {
            $tf = "$TargetFile" -replace '(?<!^)\\{2,}', '\'
            if ($tf -and (Test-Path -LiteralPath $tf) -and -not $tf.ToLower().StartsWith("c:\install-sysmon\dfir-")) {
                $tfItem = Get-Item -LiteralPath $tf -ErrorAction Stop
                if ($tfItem.Length -le 209715200) {
                    $preserved = Join-Path $tmpDir ("preserved_${ts}_" + [System.IO.Path]::GetFileName($tf))
                    Copy-Item -LiteralPath $tf -Destination $preserved -Force -ErrorAction Stop
                    Log-Detail "DFIR: preserved target before containment -> $preserved"
                } else {
                    Log-Detail "DFIR: skip preserve (ไฟล์ใหญ่เกิน 200MB): $tf"
                }
            }
        } catch { Log-Detail "DFIR: preserve failed: $($_.Exception.Message)"; $preserved = "" }

        $argList = "-NonInteractive -NoProfile -ExecutionPolicy Bypass" +
            " -File `"$dfirScript`"" +
            " -EventType `"$EventType`"" +
            " -IOCValue `"$IOCValue`"" +
            " -IOCType `"$IOCType`"" +
            " -AlertFile `"$tmpFile`"" +
            " -TargetFile `"$TargetFile`"" +
            " -PreservedFile `"$preserved`"" +
            " -ProcessImage `"$ProcessImage`"" +
            " -ProcessId `"$ProcessId`"" +
            " -ParentImage `"$ParentImage`"" +
            " -DestinationIp `"$DestinationIp`"" +
            " -Domain `"$Domain`"" +
            " -AgentName `"$AgentName`""

        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -WindowStyle Hidden -ErrorAction SilentlyContinue
        Log-Detail "DFIR: Background started (EventType=$EventType IOC=$IOCValue)"
    } catch {
        Log-Detail "DFIR: Launch failed: $($_.Exception.Message)"
    }
}

# System roots used only for the fail-closed branch below (when a file's signature
# cannot be read, refuse it if it sits in a system root).
$protectedSystemPaths = @(
    "C:\Windows\System32\",
    "C:\Windows\SysWOW64\",
    "C:\Windows\WinSxS\",
    "C:\Windows\assembly\",
    "C:\Windows\Microsoft.NET\",
    "C:\Program Files\Windows Defender\",
    "C:\Program Files (x86)\ossec-agent\"
)

# Should we REFUSE to delete this file? $true = protect. Decide by Authenticode:
# validly signed -> protect (a contaminated feed can't make us delete a real OS
# binary; also shields signed apps from FP removal). Unsigned/tampered -> allow
# (the 4-Aug masquerade fakes). BYOVD CARVE-OUT: a signed *.sys OUTSIDE the driver
# store is a bring-your-own-vulnerable-driver (WinRing0x64.sys = incident trigger,
# validly signed) -> removable. Fail closed (throw/absent) only inside a system root.
function Test-ProtectedSystemFile {
    param([string]$path)
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    $path = $path -replace '(?<!^)\\{2,}', '\'   # 22ก.ย.69: กัน backslash ซ้อนทำให้เทียบ prefix ไม่ติด
    $lp = $path.ToLower()
    try {
        if (-not (Test-Path -LiteralPath $path)) {
            foreach ($_pp in $protectedSystemPaths) { if ($lp.StartsWith($_pp.ToLower())) { return $true } }
            return $false
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($sig.Status -eq 'Valid') {
            if ([System.IO.Path]::GetExtension($lp) -eq '.sys' -and -not ($lp.Contains('\system32\drivers\') -or $lp.Contains('\system32\driverstore\'))) {
                Log-Detail "NOT protected: validly-signed .sys outside driver store (BYOVD) $path - allowing removal"
                return $false
            }
            Log-Detail "PROTECTED: validly signed $path - refusing"
            return $true
        }
        Log-Detail "NOT protected: $path signature=$($sig.Status) - masquerade candidate, allowing"
        return $false
    } catch {
        foreach ($_pp in $protectedSystemPaths) { if ($lp.StartsWith($_pp.ToLower())) { Log-Detail "PROTECTED (fail-closed): signature check threw for $path"; return $true } }
        Log-Detail "NOT protected: signature check threw for $path (non-system path) - allowing"
        return $false
    }
}

# Hard file deletion for ACL-hardened malware (4-Aug miner hardened NTFS ACLs so
# Remove-Item returned Access denied even elevated). Order matters: clearing
# attributes and even icacls can be denied before ownership is taken, so
# takeown -> icacls /reset -> grant Administrators -> clear attributes -> retry.
# Ladder ends at delete-on-reboot. Refuses protected signed system files (also
# guards files reached via hash-locate that never passed the top-level guard).
# Returns $true if the file is gone (or scheduled for reboot deletion).
function Remove-FileHard {
    param([string]$path)
    $script:RemoveFileRebootScheduled = $false
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    if (-not (Test-Path -LiteralPath $path)) { return $true }
    if (Test-ProtectedSystemFile $path) { Log-Detail "Remove-FileHard REFUSED (protected): $path"; return $false }

    try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop } catch {}
    if (-not (Test-Path -LiteralPath $path)) { Log-Detail "Deleted (plain): $path"; return $true }

    Log-Detail "Delete denied, escalating takeown+icacls: $path"
    & takeown.exe /F "$path" /A > $null 2>&1
    & icacls.exe "$path" /reset > $null 2>&1
    & icacls.exe "$path" /grant "*S-1-5-32-544:F" > $null 2>&1
    try { (Get-Item -LiteralPath $path -Force).Attributes = 'Normal' } catch {}
    try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop } catch { Log-Detail "Delete failed after ACL reset: $($_.Exception.Message)" }
    if (-not (Test-Path -LiteralPath $path)) { Log-Detail "Deleted (after takeown/icacls): $path"; return $true }

    & cmd.exe /c "del /f /q `"$path`"" > $null 2>&1
    if (-not (Test-Path -LiteralPath $path)) { Log-Detail "Deleted (cmd del): $path"; return $true }

    try {
        if (-not ('FHmv' -as [type])) {
            Add-Type -TypeDefinition "using System;using System.Runtime.InteropServices;public class FHmv{[DllImport(`"kernel32.dll`",SetLastError=true,CharSet=CharSet.Unicode)]public static extern bool MoveFileEx(string a,string b,int f);public const int D=4;}" -ErrorAction SilentlyContinue
        }
        if ([FHmv]::MoveFileEx($path,$null,[FHmv]::D)) { $script:RemoveFileRebootScheduled = $true; Log-Detail "Scheduled delete-on-reboot: $path"; return $true }
        Log-Detail "MoveFileEx failed: $path"
    } catch { Log-Detail "MoveFileEx error: $($_.Exception.Message)" }
    return $false
}

# Hard service/driver removal for SD-hardened malware services (the 4-Aug miner
# hardened its service SD so 'sc delete' returned Access denied 5). Reset the SD
# to default, stop, delete; fall back to taking ownership of the registry key;
# last resort disable (Start=4). Returns $true if the service is gone/disabled.
function Remove-ServiceHard {
    param([string]$svc)
    if ([string]::IsNullOrWhiteSpace($svc)) { return $false }
    if (-not (Get-Service -Name $svc -ErrorAction SilentlyContinue)) { return $true }
    $defSD = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
    Log-Detail "Remove-ServiceHard: $svc (SDDL before=$((& sc.exe sdshow $svc) -join ''))"
    & sc.exe sdset $svc $defSD | Out-Null
    & sc.exe stop   $svc | Out-Null
    & sc.exe delete $svc | Out-Null
    Start-Sleep -Milliseconds 400
    if (-not (Get-Service -Name $svc -ErrorAction SilentlyContinue)) { Log-Detail "Service deleted: $svc"; return $true }

    Log-Detail "sc delete failed, escalating registry takeover: $svc"
    $rel = "SYSTEM\CurrentControlSet\Services\$svc"
    & reg.exe delete "HKLM\$rel" /f > $null 2>&1
    if (-not (Test-Path "HKLM:\$rel")) { Log-Detail "Service key removed (reg delete): $svc"; return $true }
    try {
        $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $k  = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($rel,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::TakeOwnership)
        $a  = $k.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None); $a.SetOwner($admins); $k.SetAccessControl($a)
        $a2 = $k.GetAccessControl(); $a2.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($admins,'FullControl','ContainerInherit','None','Allow'))); $k.SetAccessControl($a2)
        $k.Close()
        Remove-Item -Path "HKLM:\$rel" -Recurse -Force -ErrorAction SilentlyContinue
    } catch { Log-Detail "Service key takeover error: $($_.Exception.Message)" }
    if (-not (Test-Path "HKLM:\$rel")) { Log-Detail "Service key removed (takeown): $svc"; return $true }

    try { Set-ItemProperty "HKLM:\$rel" -Name Start -Value 4 -ErrorAction Stop; Log-Detail "Service disabled (Start=4, delete failed): $svc"; return $true }
    catch { Log-Detail "Service disable failed: $($_.Exception.Message)"; return $false }
}

# A directory too broad to sweep: the drive root or a shared OS/app root. $dir is
# attacker-controlled (parent of the alerted file), so malware dropped directly in
# System32 / Program Files / a drive root would otherwise scope the process-kill and
# service-sweep across the whole OS. In those dirs we act on the single file only.
function Test-BroadSystemDir {
    param([string]$dir)
    if ([string]::IsNullOrWhiteSpace($dir)) { return $true }
    $d  = $dir.ToLower().TrimEnd('\')
    $sr = $env:SystemRoot.ToLower().TrimEnd('\')
    $sd = $env:SystemDrive.ToLower().TrimEnd('\')
    $broad = @($sd, $sr, "$sr\system32", "$sr\system32\drivers", "$sr\system32\driverstore", "$sr\syswow64",
        "${env:ProgramFiles}".ToLower().TrimEnd('\'), "${env:ProgramFiles(x86)}".ToLower().TrimEnd('\'), "$env:ProgramData".ToLower().TrimEnd('\'))
    return ($broad -contains $d)
}

# Resolve a service ImagePath to its executable path (strip quotes, args, and
# normalize \??\ , \SystemRoot\ , relative system32\ to absolute). Used to
# signature-check the binary behind a service before removing the service.
function Get-ServiceBinary {
    param([string]$imagePath)
    if ([string]::IsNullOrWhiteSpace($imagePath)) { return "" }
    $b = $imagePath.Trim()
    if ($b.StartsWith('"')) { $b = $b.Substring(1); $q = $b.IndexOf('"'); if ($q -ge 0) { $b = $b.Substring(0,$q) } }
    else { $m = [regex]::Match($b, '^(.*?\.(?:exe|sys|dll))(?:\s|$)', 'IgnoreCase'); if ($m.Success) { $b = $m.Groups[1].Value } }
    $bl = $b.ToLower(); $sr = $env:SystemRoot.ToLower()
    return ($bl -replace '^\\\?\?\\','' -replace '^\\systemroot\\', ($sr + '\') -replace '^system32\\', ($sr + '\system32\'))
}

# Kill every process whose image lives under $Dir in one pass; return their image
# paths (the validated delete candidates). SIGNATURE-GATED: a validly-signed OS
# process is never killed (a mis-scoped $dir must not terminate lsass/svchost).
function Get-ClusterProcs {
    param([string]$Dir)
    $paths = @()
    if ([string]::IsNullOrWhiteSpace($Dir)) { return $paths }
    $dl = $Dir.ToLower()
    try {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.ToLower().StartsWith($dl) } | ForEach-Object {
            if (Test-ProtectedSystemFile $_.ExecutablePath) { Log-Detail "Cluster SKIP (signed/protected): PID $($_.ProcessId) $($_.ExecutablePath)"; return }
            $paths += $_.ExecutablePath
            try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Log-Detail "Killed cluster PID $($_.ProcessId): $($_.ExecutablePath)" } catch {}
        }
    } catch { Log-Detail "Get-ClusterProcs error: $($_.Exception.Message)" }
    return ($paths | Select-Object -Unique)
}

# The self-heal survived Normal-mode eradication. Flag for manual Safe Mode; never
# auto-reboot a clinical endpoint.
function Write-SafeModeMarker {
    param([string]$TargetFile,[string]$Dir,[string]$Hash,[string[]]$Services)
    $marker = "C:\install-sysmon\NEEDS_MANUAL_SAFEMODE.txt"
    $stamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $body = "[$stamp] CONTAINMENT COULD NOT ERADICATE IN NORMAL MODE - MANUAL SAFE MODE REQUIRED`r`n" +
            "  Target (keeps re-dropping): $TargetFile`r`n  Malicious dir: $Dir`r`n" +
            "  IOC sha256: $Hash`r`n  Services neutralized: $($Services -join ', ')`r`n" +
            "  A self-heal watchdog survived. Boot Safe Mode (Minimal) and run the phase2 remover. Do NOT ignore.`r`n"
    try { if (-not (Test-Path 'C:\install-sysmon')) { New-Item -ItemType Directory -Path 'C:\install-sysmon' -Force | Out-Null }; Add-Content -LiteralPath $marker -Value $body -Encoding UTF8; Log-Detail "CONTAINMENT: wrote Safe Mode marker $marker" } catch { Log-Detail "Marker write failed: $($_.Exception.Message)" }
}

# Watchdog-aware containment. Order: neutralize services pointing into the malicious
# dir (self-heal watchdog is usually a SYSTEM service - kill FIRST) -> kill cluster
# processes -> hard-delete target + cluster exes -> verify loop. Every op is signature
# gated and file-specific (never blanket-deletes a dir; protects Protect\ DPAPI and
# signed files). Per-dir lock stops overlapping runs.
function Invoke-Containment {
    param([string]$TargetFile,[string]$ProcessId = "",[string]$Hash = "")
    if ([string]::IsNullOrWhiteSpace($TargetFile)) { return }
    $dir = Split-Path -Parent $TargetFile
    $tmpDir = "C:\install-sysmon\dfir-tmp"
    try { if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null } } catch {}
    $safe = ($dir.ToLower() -replace '[^a-z0-9]','_'); if ($safe.Length -gt 80) { $safe = $safe.Substring($safe.Length-80) }
    $lock = Join-Path $tmpDir "contain_$safe.lock"
    if (Test-Path $lock) {
        $age = (Get-Date) - (Get-Item $lock).LastWriteTime
        if ($age.TotalSeconds -lt 90) { Log-Detail "CONTAINMENT: already running for $dir (lock $([int]$age.TotalSeconds)s) - skip"; return }
    }
    try { Set-Content -LiteralPath $lock -Value (Get-Date -Format o) -Force } catch {}

    try {
        # $dir is attacker-controlled (parent of the alerted file). If it is a broad
        # system/app root, dir-scoped process-kill and service-sweep would hit the whole
        # OS, so restrict to the single alerted file. Narrow (masquerade sub)dirs like
        # System32\Microsoft still get the full watchdog sweep.
        $broadDir = Test-BroadSystemDir $dir
        Log-Detail "CONTAINMENT start: target=$TargetFile dir=$dir broadDir=$broadDir"

        # 1. services whose ImagePath references target/dir. Full-path match only (never
        # bare filename - masquerade reuses names like SearchIndexer.exe); normalize
        # relative driver paths first; SIGNATURE-GATED (never remove a signed-binary
        # service); skipped entirely in a broad dir.
        $sysroot = $env:SystemRoot.ToLower()
        $tgtLower = $TargetFile.ToLower(); $dirLower = if ($dir) { $dir.ToLower() } else { "" }
        $killedSvc = @()
        if (-not $broadDir) {
            try {
                Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
                    $ip = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ImagePath
                    if ($ip) {
                        $ipn = $ip.ToLower().Trim().Trim('"')
                        $ipn = $ipn -replace '^\\\?\?\\','' -replace '^\\systemroot\\', ($sysroot + '\') -replace '^system32\\', ($sysroot + '\system32\')
                        if ($ipn.Contains($tgtLower) -or ($dirLower -and $ipn.Contains($dirLower))) {
                            if (Test-ProtectedSystemFile (Get-ServiceBinary $ip)) { Log-Detail "CONTAINMENT: SKIP service '$($_.PSChildName)' - backed by signed binary ($ip)" }
                            else {
                                Log-Detail "CONTAINMENT: service '$($_.PSChildName)' ImagePath=$ip -> Remove-ServiceHard"
                                if (Remove-ServiceHard $_.PSChildName) { $killedSvc += $_.PSChildName }
                            }
                        }
                    }
                }
            } catch { Log-Detail "CONTAINMENT service scan error: $($_.Exception.Message)" }
        }

        # 2. kill known PID + processes running from the dir (whole dir if narrow;
        # only the exact target file if broad). Get-ClusterProcs is signature-gated.
        if ($ProcessId) { try { Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue; Log-Detail "Killed alert PID $ProcessId" } catch {} }
        $clusterPaths = @()
        if ($broadDir) {
            try { Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.ToLower() -eq $tgtLower } | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Log-Detail "Killed target PID $($_.ProcessId)" } catch {} } } catch {}
        } else {
            $clusterPaths = Get-ClusterProcs -Dir $dir
        }

        # 3. delete target + the validated cluster executables
        Remove-FileHard $TargetFile | Out-Null
        $rebootPending = $script:RemoveFileRebootScheduled   # loaded driver/DLL: deletes only on reboot
        foreach ($cp in $clusterPaths) { if ($cp -ne $TargetFile) { Remove-FileHard $cp | Out-Null } }

        # 4. verify loop - a self-heal watchdog re-drops within ~10s. A file that is
        # merely present-but-scheduled-for-reboot-delete is NOT a re-drop; treat it as
        # success-pending-reboot, never as a surviving watchdog.
        $clean = $false
        for ($i=1; $i -le 3; $i++) {
            Start-Sleep -Seconds 11
            if (-not (Test-Path -LiteralPath $TargetFile)) { $clean = $true; Log-Detail "CONTAINMENT: target absent on verify pass $i"; break }
            if ($rebootPending) { $clean = $true; Log-Detail "CONTAINMENT: target present but delete scheduled on reboot (pass $i) - reboot required"; break }
            Log-Detail "CONTAINMENT: target RE-DROPPED (pass $i) - watchdog alive, re-neutralizing"
            if (-not $broadDir) { Get-ClusterProcs -Dir $dir | Out-Null }
            Remove-FileHard $TargetFile | Out-Null
            $rebootPending = $script:RemoveFileRebootScheduled
        }

        if ($clean) {
            if (Test-Path -LiteralPath $TargetFile) { Log-Detail "CONTAINMENT OK (REBOOT REQUIRED): $TargetFile scheduled for delete-on-reboot; services removed: $($killedSvc -join ',')" }
            else { Log-Detail "CONTAINMENT SUCCESS: $TargetFile removed; services removed: $($killedSvc -join ',')" }
        } else {
            Write-SafeModeMarker -TargetFile $TargetFile -Dir $dir -Hash $Hash -Services $killedSvc
        }
    } finally { try { Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue } catch {} }
}

# Mode B locate: an alert can carry a sha256 IOC but no on-disk path (e.g. Sysmon
# EID6 driver-load arriving metadata-only). Hunt a bounded set of common malware
# drop dirs for a file matching the hash. Only executables under 100MB are hashed;
# scan is depth-limited to stay fast. Returns the path or $null.
function Find-ByHash {
    param([string]$Sha256)
    if ([string]::IsNullOrWhiteSpace($Sha256)) { return $null }
    $dirs = @("$env:SystemRoot\System32\Microsoft","$env:SystemRoot\Temp","$env:ProgramData","$env:PUBLIC","$env:TEMP","$env:LOCALAPPDATA\Temp") | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    foreach ($d in $dirs) {
        try {
            $files = Get-ChildItem -LiteralPath $d -Recurse -File -Force -Depth 3 -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 100MB -and $_.Extension -match '^\.(exe|dll|sys|scr|com)$' }
            foreach ($fi in $files) {
                try { if ((Get-FileHash -LiteralPath $fi.FullName -Algorithm SHA256).Hash.ToUpper() -eq $Sha256) { Log-Detail "Find-ByHash: located $($fi.FullName)"; return $fi.FullName } } catch {}
            }
        } catch {}
    }
    return $null
}

# Confirm an on-disk file is the IOC. TRUE if SHA256 matches OR the file exists but
# is unreadable (ACL-hardened malware blocks even elevated Get-FileHash - the 4-Aug
# anti-forensic move; the IOC came from this path's Sysmon hash so we trust it and let
# Remove-FileHard's own guard protect system files). FALSE only on definite mismatch
# or absence.
function Confirm-IocFile {
    param([string]$path,[string]$ioc)
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $fh = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpper()
        if ($fh -eq $ioc) { Log-Detail "Confirm-IocFile: hash match $path"; return $true }
        Log-Detail "Confirm-IocFile: on-disk hash $fh != IOC $ioc ($path) - not a match"
        return $false
    } catch {
        Log-Detail "Confirm-IocFile: $path unreadable ($($_.Exception.Message)) - trusting alert IOC, treating as match"
        return $true
    }
}

Log-Detail "=== AR SCRIPT STARTED (PowerShell) ==="

# 1. Read STDIN
$inputJson = ""
try {
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    $inputJson = Read-Host
    Log-Detail "Read-Host success. Length: $($inputJson.Length)"
} catch { Log-Detail "Read-Host failed: $($_.Exception.Message)" }

if ([string]::IsNullOrWhiteSpace($inputJson)) {
    try {
        $lines = @()
        while ($line = [Console]::In.ReadLine()) { $lines += $line }
        $inputJson = $lines -join "`n"
        Log-Detail "Fallback read success. Length: $($inputJson.Length)"
    } catch { Log-Detail "Fallback failed" }
}

if ([string]::IsNullOrWhiteSpace($inputJson)) { Log-Detail "CRITICAL: Empty input"; exit 1 }

$preview = if ($inputJson.Length -gt 2000) { $inputJson.Substring(0,2000) + "..." } else { $inputJson }
Log-Detail "INPUT PREVIEW:"
Log-Detail $preview

# 2. Parse JSON
try {
    $INPUT_ARRAY = $inputJson | ConvertFrom-Json
    Log-Detail "JSON parsed OK"
} catch { Log-Detail "JSON parse failed"; exit 1 }

$command = $INPUT_ARRAY.command
$alert   = $INPUT_ARRAY.parameters.alert

# 22ก.ย.69 - บันทึกบริบทของ AR ให้ SIEM เห็น (ต้องอยู่ก่อน GUARD ทุกตัว
# เพื่อให้แม้กรณี early exit ก็ยังมีหลักฐานว่า AR ถูกสั่งด้วยเหตุใด)
Log-ARJson $command $alert $INPUT_ARRAY.parameters.program

# GUARD 25may2569: prevent AR loop — early exit if alert points at a file
# already inside our own dfir-found collection folder. Sysmon Event 11/29
# fires on every DFIR copy (same hash); without this guard the AR re-triggers
# Invoke-DFIRCollection.ps1, which copies the file again with _DFIR_COPY suffix,
# infinitely.
# 22ก.ย.69: ขยายจาก dfir-found -> "dfir-" เพื่อครอบ dfir-tmp (ที่เก็บสำเนา preserved) ด้วย
# มิฉะนั้นสำเนาหลักฐานจะถูก AR รอบถัดไปลบทิ้ง และเกิด loop
$dfirRootGuard = "C:\install-sysmon\dfir-"
$npTarget = Normalize-AlertPath $alert.data.win.eventdata.targetFilename
$npImage  = Normalize-AlertPath $alert.data.win.eventdata.image
$npLoaded = Normalize-AlertPath $alert.data.win.eventdata.imageLoaded
$npSysck  = Normalize-AlertPath $alert.syscheck.path
$guardCandidates = @($npTarget, $npImage, $npLoaded, $npSysck) | Where-Object { $_ }
foreach ($_gp in $guardCandidates) {
    if ($_gp.ToLower().StartsWith($dfirRootGuard.ToLower())) {
        Log-Detail "EARLY EXIT: alert targets file inside dfir-found ($_gp) - skipping to prevent AR loop"
        exit 0
    }
}

# GUARD (see Test-ProtectedSystemFile): the MISP feed has shipped hashes of
# genuine Windows binaries (gcapi.dll 19 may, SysWOW64\rundll32.exe 25 may). If
# such a hash matches a signed OS file, refuse and exit. Unsigned masquerade
# files under a system path fall through to normal containment.
# 22ก.ย.69 FIX: เดิม guard นี้วน $guardCandidates ซึ่งรวม eventdata.image
# แต่ Event 15/26/29 นั้น image = โปรเซสผู้กระทำ (เช่น Explorer.EXE, cmd.exe) ไม่ใช่เป้าหมาย
# ทำให้ไฟล์อันตรายที่ถูกสร้างโดยโปรแกรมระบบที่เซ็นถูกต้อง รอดจากการกำจัดทุกครั้ง
# -> ตรวจเฉพาะ path ที่เป็น "เป้าหมายของ IoC" ตามชนิดเหตุการณ์
# (ไฟล์ระบบยังถูกปกป้องอีก 3 ชั้นที่จุดลงมือจริง: Remove-FileHard / kill cluster / service removal)
$evForGuard = "$($alert.data.win.system.eventID)"
switch ($evForGuard) {
    "1"     { $iocTargetCandidates = @($npImage) }
    "6"     { $iocTargetCandidates = @($npLoaded) }
    "7"     { $iocTargetCandidates = @($npLoaded) }
    "15"    { $iocTargetCandidates = @($npTarget) }
    "26"    { $iocTargetCandidates = @($npTarget) }
    "29"    { $iocTargetCandidates = @($npTarget) }
    default { $iocTargetCandidates = $guardCandidates }
}
$iocTargetCandidates = @($iocTargetCandidates + @($npSysck)) | Where-Object { $_ }
Log-Detail "Authenticode gate scope (EventID=$evForGuard): $($iocTargetCandidates -join ' | ')"
foreach ($_gp in $iocTargetCandidates) {
    if (Test-ProtectedSystemFile $_gp) {
        Log-Detail "EARLY EXIT (protected signed system file): $_gp - refusing kill/delete"
        exit 0
    }
}

# 3. Extract IOC
$IOCvalue = $null; $IOCtype = $null; $IOCmode = $null
$eventID    = $alert.data.win.system.eventID
$hashes_val = $alert.data.win.eventdata.hashes
$hash_val   = $alert.data.win.eventdata.hash

$hashField = $null; $hashFieldName = ""
if ($eventID -in @("1","6","7","26","29") -and $hashes_val) { $hashField = $hashes_val; $hashFieldName = "hashes" }
elseif ($eventID -eq "15" -and $hash_val)                    { $hashField = $hash_val;   $hashFieldName = "hash" }
elseif ($hashes_val)                                          { $hashField = $hashes_val; $hashFieldName = "hashes(fb)" }
elseif ($hash_val)                                            { $hashField = $hash_val;   $hashFieldName = "hash(fb)" }

if ($hashField -and $hashField -match "SHA256=([A-Fa-f0-9]{64})") {
    $IOCvalue = $matches[1].ToUpper(); $IOCtype = "sha256"; $IOCmode = "Sysmon"
    Log-Detail "Mode A: Sysmon (EventID=$eventID field=$hashFieldName) IOC=$IOCvalue"
}
if (-not $IOCvalue -and $alert.syscheck.sha256_after) {
    $IOCvalue = ($alert.syscheck.sha256_after).ToUpper(); $IOCtype = "sha256"; $IOCmode = "FIM"
    Log-Detail "Mode B: FIM IOC=$IOCvalue"
}
if (-not $IOCvalue) {
    if ($eventID -eq "3" -and $alert.data.win.eventdata.destinationIp) {
        $IOCvalue = $alert.data.win.eventdata.destinationIp; $IOCtype = "ip"; $IOCmode = "Event3"
        Log-Detail "Mode D: Event3 IP=$IOCvalue"
    } elseif ($eventID -eq "22" -and $alert.data.win.eventdata.queryName) {
        $IOCvalue = $alert.data.win.eventdata.queryName; $IOCtype = "domain"; $IOCmode = "Event22"
        Log-Detail "Mode D: Event22 Domain=$IOCvalue"
    }
}
if (-not $IOCvalue) { Log-Detail "No IOC - EXIT"; exit 0 }
Log-Detail "IOC FINAL: $IOCvalue ($IOCtype) mode=$IOCmode"

# 4. Extract Fields
$agentName       = $alert.agent.name
$imagePathGlobal = $alert.data.win.eventdata.image
$processId       = $alert.data.win.eventdata.processId
$parentImage     = $alert.data.win.eventdata.parentImage
$commandLine     = $alert.data.win.eventdata.commandLine
$userName        = $alert.data.win.eventdata.user
$filePath        = $alert.syscheck.path
Log-Detail "Image(global): $imagePathGlobal | Syscheck: $filePath | Agent: $agentName"

$handledBySpecificBlock = $eventID -in @("1","6","7","15","26","29")

# Does any path field in this alert actually point at a file on disk? If not, and we
# still hold a sha256 IOC, this is a metadata-only alert (Mode B) handled after the
# specific blocks by hash-locating the file in known drop dirs.
$anyDiskTarget = @($imagePathGlobal, $alert.data.win.eventdata.imageLoaded, $alert.data.win.eventdata.targetFilename, $filePath) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

# 5. Generic fallback
if ($IOCtype -eq "sha256" -and $imagePathGlobal -and -not $handledBySpecificBlock) {
    if (Confirm-IocFile $imagePathGlobal $IOCvalue) {
        Log-Detail "Generic MATCH (EventID=$eventID)"
        Start-DFIRBackground -EventType "Sysmon_Generic_${eventID}" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $imagePathGlobal -ProcessImage $imagePathGlobal -ProcessId $processId -AgentName $agentName
        Invoke-Containment -TargetFile $imagePathGlobal -ProcessId $processId -Hash $IOCvalue
    } else { Log-Detail "Generic: no match" }
}

# 5b. Event 1
if ($IOCtype -eq "sha256" -and $eventID -eq "1") {
    $ev1_img = $alert.data.win.eventdata.image
    $ev1_pid = $alert.data.win.eventdata.processId
    Log-Detail "Event 1: $ev1_img (PID=$ev1_pid)"
    $ev1_match = Confirm-IocFile $ev1_img $IOCvalue

    Start-DFIRBackground -EventType "Event1" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -ProcessImage $ev1_img -ProcessId $ev1_pid -ParentImage $parentImage -AgentName $agentName

    if ($ev1_match) { Invoke-Containment -TargetFile $ev1_img -ProcessId $ev1_pid -Hash $IOCvalue }
}

# 5c. Event 6
if ($IOCtype -eq "sha256" -and $eventID -eq "6") {
    $ev6_drv = $alert.data.win.eventdata.imageLoaded
    Log-Detail "Event 6: driver=$ev6_drv"
    Start-DFIRBackground -EventType "Event6" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev6_drv -AgentName $agentName
    if (Confirm-IocFile $ev6_drv $IOCvalue) { Invoke-Containment -TargetFile $ev6_drv -Hash $IOCvalue }
    else { Log-Detail "Event6: no match" }
}

# 5d. Event 7
if ($IOCtype -eq "sha256" -and $eventID -eq "7") {
    $ev7_dll  = $alert.data.win.eventdata.imageLoaded
    $ev7_proc = $alert.data.win.eventdata.image
    Log-Detail "Event 7: dll=$ev7_dll loadedBy=$ev7_proc"
    $ev7_match = Confirm-IocFile $ev7_dll $IOCvalue
    Start-DFIRBackground -EventType "Event7" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev7_dll -ProcessImage $ev7_proc -AgentName $agentName
    if ($ev7_match) { Invoke-Containment -TargetFile $ev7_dll -Hash $IOCvalue }
}

# 5e. Event 15
if ($IOCtype -eq "sha256" -and $eventID -eq "15") {
    $ev15_tgt = $alert.data.win.eventdata.targetFilename
    $ev15_src = $alert.data.win.eventdata.image
    Log-Detail "Event 15: targetFile=$ev15_tgt writtenBy=$ev15_src"
    if (Confirm-IocFile $ev15_tgt $IOCvalue) {
        Log-Detail "Event 15: MATCH -> containment"
        Start-DFIRBackground -EventType "Event15" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev15_tgt -ProcessImage $ev15_src -AgentName $agentName
        Invoke-Containment -TargetFile $ev15_tgt -Hash $IOCvalue
    } else { Log-Detail "Event15: no match" }
}

# 5f. Event 26
if ($IOCtype -eq "sha256" -and $eventID -eq "26") {
    $ev26_tgt = $alert.data.win.eventdata.targetFilename
    $ev26_img = $alert.data.win.eventdata.image
    Log-Detail "Event 26 (File Delete Detected): $ev26_tgt"
    Start-DFIRBackground -EventType "Event26" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev26_tgt -ProcessImage $ev26_img -AgentName $agentName
    if (Confirm-IocFile $ev26_tgt $IOCvalue) { Invoke-Containment -TargetFile $ev26_tgt -Hash $IOCvalue }
    elseif (Test-Path -LiteralPath $ev26_tgt) { Log-Detail "Event26: no match" }
    else { Log-Detail "Event26: Original gone - checking Sysmon archive" }
    foreach ($ad in @("C:\Sysmon","C:\Windows\Sysmon","C:\ProgramData\Sysmon")) {
        if (Test-Path $ad) { $af = Join-Path $ad $IOCvalue; if (Test-Path $af) { try { Remove-Item $af -Force; Log-Detail "Event26: Deleted archive: $af" } catch { Log-Detail "Event26: Delete archive failed: $($_.Exception.Message)" } } else { Log-Detail "Event26: No archive at: $af" } }
    }
    if ($ev26_img) { Log-Detail "Event26: triggered by: $ev26_img"; Log-Detail "NOTE: Review '$ev26_img' manually if suspicious" }
}

# 5g. Event 29
if ($IOCtype -eq "sha256" -and $eventID -eq "29") {
    $ev29_tgt = $alert.data.win.eventdata.targetFilename
    $ev29_img = $alert.data.win.eventdata.image
    Log-Detail "Event 29 (File Executable Detected): $ev29_tgt"
    if (Confirm-IocFile $ev29_tgt $IOCvalue) {
        Log-Detail "Event 29: MATCH -> containment"
        Start-DFIRBackground -EventType "Event29" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev29_tgt -ProcessImage $ev29_img -AgentName $agentName
        Invoke-Containment -TargetFile $ev29_tgt -Hash $IOCvalue
    } else { Log-Detail "Event29: no match" }
}

# 6. FIM
if ($IOCtype -eq "sha256" -and $filePath) {
    if (Confirm-IocFile $filePath $IOCvalue) {
        Log-Detail "FIM MATCH -> containment"
        Start-DFIRBackground -EventType "FIM" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $filePath -AgentName $agentName
        Invoke-Containment -TargetFile $filePath -Hash $IOCvalue
    } else { Log-Detail "FIM: no match" }
}

# 6b. Mode B: metadata-only alert carried a sha256 but no event field points at a
# file on disk. Hash-locate in known drop dirs and contain what we find. Guarded so
# it only runs when no specific block already had an on-disk target to act on.
if ($IOCtype -eq "sha256" -and -not $anyDiskTarget) {
    Log-Detail "Mode B: no on-disk target in alert fields - hash-locating $IOCvalue"
    $located = Find-ByHash -Sha256 $IOCvalue
    if ($located) { Invoke-Containment -TargetFile $located -Hash $IOCvalue }
    else { Log-Detail "Mode B: hash not located in known drop dirs" }
}

# 7. Network Block (Event 3)
$winSystem    = $alert.data.win.system
$winEventdata = $alert.data.win.eventdata

if ($winSystem.eventID -eq '3') {
    $ip = $winEventdata.destinationIp
    if ($ip) {
        Start-DFIRBackground -EventType "Event3" -IOCValue $ip -IOCType "ip" -AlertJson $inputJson -ProcessImage $winEventdata.image -DestinationIp $ip -AgentName $agentName
        $ruleName = "Wazuh AR Block $ip"
        if ($command -eq "add") { New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $ip -Protocol Any; Log-Detail "Blocked IP: $ip" }
        elseif ($command -eq "delete") { Remove-NetFirewallRule -DisplayName $ruleName -EA SilentlyContinue; Log-Detail "Unblocked IP: $ip" }
    }
}

# 8. Domain Block (Event 22)
if ($winSystem.eventID -eq '22') {
    $domain    = $winEventdata.queryName
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    if ($domain) {
        Start-DFIRBackground -EventType "Event22" -IOCValue $domain -IOCType "domain" -AlertJson $inputJson -ProcessImage $winEventdata.image -Domain $domain -AgentName $agentName
        if (-not (Select-String $hostsPath $domain -Quiet)) { Add-Content $hostsPath "127.0.0.1`t$domain"; Log-Detail "Blocked domain: $domain" }
    }
}

Log-Detail "=== AR SCRIPT ENDED ==="
exit 0