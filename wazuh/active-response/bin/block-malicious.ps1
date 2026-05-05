################################
## Wazuh Active Response (FINAL)
## Supports: MISP + Sysmon + FIM
## Sysmon Events: 1, 3, 6, 7, 15, 22, 26, 29
## DFIR Collection: C:\install-sysmon\dfir-found\ (background job)
##
## Architecture:
##   Main script  -> IOC extract -> kill/delete -> return (~2 sec)
##   Invoke-DFIRCollection.ps1 -> background job แยก ไม่ block main
################################

$logFile    = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$dfirScript = "C:\install-sysmon\Invoke-DFIRCollection.ps1"

function Log-Detail {
    param([string]$msg)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $msg" | Out-File -FilePath $logFile -Append -Encoding utf8
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

        $argList = "-NonInteractive -NoProfile -ExecutionPolicy Bypass" +
            " -File `"$dfirScript`"" +
            " -EventType `"$EventType`"" +
            " -IOCValue `"$IOCValue`"" +
            " -IOCType `"$IOCType`"" +
            " -AlertFile `"$tmpFile`"" +
            " -TargetFile `"$TargetFile`"" +
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

# 5. Generic fallback
if ($IOCtype -eq "sha256" -and $imagePathGlobal -and -not $handledBySpecificBlock) {
    if (Test-Path $imagePathGlobal) {
        try {
            $fh = (Get-FileHash $imagePathGlobal -Algorithm SHA256).Hash.ToUpper()
            if ($fh -eq $IOCvalue) {
                Log-Detail "Generic HASH MATCH (EventID=$eventID)"
                Start-DFIRBackground -EventType "Sysmon_Generic_${eventID}" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $imagePathGlobal -ProcessImage $imagePathGlobal -ProcessId $processId -AgentName $agentName
                if ($processId) { try { Stop-Process -Id $processId -Force; Log-Detail "Killed PID: $processId" } catch {} }
                try { Remove-Item $imagePathGlobal -Force; Log-Detail "Deleted: $imagePathGlobal" } catch { Log-Detail "Delete failed: $($_.Exception.Message)" }
            } else { Log-Detail "Generic: hash mismatch" }
        } catch { Log-Detail "Generic error: $($_.Exception.Message)" }
    }
}

# 5b. Event 1
if ($IOCtype -eq "sha256" -and $eventID -eq "1") {
    $ev1_img = $alert.data.win.eventdata.image
    $ev1_pid = $alert.data.win.eventdata.processId
    Log-Detail "Event 1: $ev1_img (PID=$ev1_pid)"
    $ev1_match = $false
    if ($ev1_img -and (Test-Path $ev1_img)) {
        try { $fh = (Get-FileHash $ev1_img -Algorithm SHA256).Hash.ToUpper(); Log-Detail "Event1 file=$fh IOC=$IOCvalue"; if ($fh -eq $IOCvalue) { $ev1_match = $true } else { Log-Detail "Event1: mismatch" } } catch { Log-Detail "Event1 hash error: $($_.Exception.Message)" }
    } else { Log-Detail "Event1: image not on disk: $ev1_img" }

    Start-DFIRBackground -EventType "Event1" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -ProcessImage $ev1_img -ProcessId $ev1_pid -ParentImage $parentImage -AgentName $agentName

    if ($ev1_match) {
        if ($ev1_pid) { try { Stop-Process -Id $ev1_pid -Force; Log-Detail "Killed PID: $ev1_pid" } catch { Log-Detail "Kill PID failed: $($_.Exception.Message)" } }
        if ($ev1_img) { try { Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $ev1_img } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Log-Detail "Killed matching PID: $($_.ProcessId)" } } catch {} }
        Start-Sleep -Seconds 1
        if ($ev1_img -and (Test-Path $ev1_img)) { try { Remove-Item $ev1_img -Force; Log-Detail "Deleted: $ev1_img" } catch { Log-Detail "Delete failed: $($_.Exception.Message)" } }
    }
}

# 5c. Event 6
if ($IOCtype -eq "sha256" -and $eventID -eq "6") {
    $ev6_drv = $alert.data.win.eventdata.imageLoaded
    Log-Detail "Event 6: driver=$ev6_drv"
    Start-DFIRBackground -EventType "Event6" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev6_drv -AgentName $agentName
    if ($ev6_drv -and (Test-Path $ev6_drv)) {
        try {
            $fh = (Get-FileHash $ev6_drv -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event6 file=$fh IOC=$IOCvalue"
            if ($fh -eq $IOCvalue) {
                try {
                    Add-Type -TypeDefinition "using System; using System.Runtime.InteropServices; public class FHDrv { [DllImport(`"kernel32.dll`",SetLastError=true,CharSet=CharSet.Unicode)] public static extern bool MoveFileEx(string a,string b,int f); public const int D=4; }" -ErrorAction SilentlyContinue
                    if ([FHDrv]::MoveFileEx($ev6_drv,$null,[FHDrv]::D)) { Log-Detail "Scheduled driver delete on reboot: $ev6_drv" } else { Log-Detail "MoveFileEx failed (Event6)" }
                } catch { Log-Detail "Driver delete error: $($_.Exception.Message)" }
                try { $n=[System.IO.Path]::GetFileNameWithoutExtension($ev6_drv); $s=Get-Service -Name $n -EA SilentlyContinue; if($s){Stop-Service $n -Force -EA SilentlyContinue;Set-Service $n -StartupType Disabled;Log-Detail "Disabled service: $n"} } catch {}
            } else { Log-Detail "Event6: mismatch" }
        } catch { Log-Detail "Event6 error: $($_.Exception.Message)" }
    }
}

# 5d. Event 7
if ($IOCtype -eq "sha256" -and $eventID -eq "7") {
    $ev7_dll  = $alert.data.win.eventdata.imageLoaded
    $ev7_proc = $alert.data.win.eventdata.image
    Log-Detail "Event 7: dll=$ev7_dll loadedBy=$ev7_proc"
    $ev7_match = $false
    if ($ev7_dll -and (Test-Path $ev7_dll)) {
        try { $fh=(Get-FileHash $ev7_dll -Algorithm SHA256).Hash.ToUpper(); Log-Detail "Event7 file=$fh IOC=$IOCvalue"; if($fh -eq $IOCvalue){$ev7_match=$true}else{Log-Detail "Event7: mismatch"} } catch { Log-Detail "Event7 hash error: $($_.Exception.Message)" }
    } else { Log-Detail "Event7: DLL not found: $ev7_dll" }
    Start-DFIRBackground -EventType "Event7" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev7_dll -ProcessImage $ev7_proc -AgentName $agentName
    if ($ev7_match) {
        try { Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $ev7_proc } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue; Log-Detail "Killed PID: $($_.ProcessId)" } } catch { Log-Detail "Kill process failed: $($_.Exception.Message)" }
        Start-Sleep -Seconds 2
        if ($ev7_dll -and (Test-Path $ev7_dll)) {
            try { Remove-Item $ev7_dll -Force; Log-Detail "Deleted DLL: $ev7_dll" }
            catch {
                try { Add-Type -TypeDefinition "using System; using System.Runtime.InteropServices; public class FHDll { [DllImport(`"kernel32.dll`",SetLastError=true,CharSet=CharSet.Unicode)] public static extern bool MoveFileEx(string a,string b,int f); public const int D=4; }" -EA SilentlyContinue; if([FHDll]::MoveFileEx($ev7_dll,$null,[FHDll]::D)){Log-Detail "Scheduled DLL delete on reboot: $ev7_dll"}else{Log-Detail "MoveFileEx failed (Event7)"} } catch { Log-Detail "Schedule failed (Event7): $($_.Exception.Message)" }
            }
        }
    }
}

# 5e. Event 15
if ($IOCtype -eq "sha256" -and $eventID -eq "15") {
    $ev15_tgt = $alert.data.win.eventdata.targetFilename
    $ev15_src = $alert.data.win.eventdata.image
    Log-Detail "Event 15: targetFile=$ev15_tgt writtenBy=$ev15_src"
    if ($ev15_tgt -and (Test-Path $ev15_tgt)) {
        try {
            $fh = (Get-FileHash $ev15_tgt -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event15 file=$fh IOC=$IOCvalue"
            if ($fh -eq $IOCvalue) {
                Log-Detail "Event 15: HASH MATCH -> kill + delete"
                Start-DFIRBackground -EventType "Event15" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev15_tgt -ProcessImage $ev15_src -AgentName $agentName
                try { Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*$ev15_tgt*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue; Log-Detail "Event15: Killed PID $($_.ProcessId)" } } catch { Log-Detail "Event15: Kill failed: $($_.Exception.Message)" }
                $handleExe = "C:\Tools\handle64.exe"
                if (Test-Path $handleExe) { try { & $handleExe -accepteula -nobanner "$ev15_tgt" 2>&1 | ForEach-Object { if ($_ -match "pid: (\d+)") { Stop-Process -Id $matches[1] -Force -EA SilentlyContinue; Log-Detail "Event15: Killed handle PID $($matches[1])" } } } catch { Log-Detail "handle64 failed: $($_.Exception.Message)" } }
                Start-Sleep -Seconds 2
                try { Remove-Item $ev15_tgt -Force; Log-Detail "Event15: Deleted: $ev15_tgt" }
                catch {
                    $del = $false
                    try { Start-Process "cmd.exe" -ArgumentList "/c del /f /q `"$ev15_tgt`"" -WindowStyle Hidden -Wait; if(-not(Test-Path $ev15_tgt)){$del=$true;Log-Detail "Event15: Deleted via cmd"} } catch {}
                    if (-not $del) { try { Add-Type -TypeDefinition "using System; using System.Runtime.InteropServices; public class FH15 { [DllImport(`"kernel32.dll`",SetLastError=true,CharSet=CharSet.Unicode)] public static extern bool MoveFileEx(string a,string b,int f); public const int D=4; }" -EA SilentlyContinue; if([FH15]::MoveFileEx($ev15_tgt,$null,[FH15]::D)){Log-Detail "Event15: Scheduled delete on reboot"}else{Log-Detail "Event15: MoveFileEx failed"} } catch { Log-Detail "Event15: All delete failed: $($_.Exception.Message)" } }
                }
            } else { Log-Detail "Event15: mismatch (file=$fh IOC=$IOCvalue)" }
        } catch { Log-Detail "Event15 error: $($_.Exception.Message)" }
    } else { Log-Detail "Event15: targetFile not found: $ev15_tgt" }
}

# 5f. Event 26
if ($IOCtype -eq "sha256" -and $eventID -eq "26") {
    $ev26_tgt = $alert.data.win.eventdata.targetFilename
    $ev26_img = $alert.data.win.eventdata.image
    Log-Detail "Event 26 (File Delete Detected): $ev26_tgt"
    Start-DFIRBackground -EventType "Event26" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev26_tgt -ProcessImage $ev26_img -AgentName $agentName
    if ($ev26_tgt -and (Test-Path $ev26_tgt)) {
        try {
            $fh = (Get-FileHash $ev26_tgt -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event26 file=$fh IOC=$IOCvalue"
            if ($fh -eq $IOCvalue) { try { Remove-Item $ev26_tgt -Force; Log-Detail "Event26: Deleted original: $ev26_tgt" } catch { Log-Detail "Event26: Delete failed: $($_.Exception.Message)" } }
            else { Log-Detail "Event26: mismatch" }
        } catch { Log-Detail "Event26 hash error: $($_.Exception.Message)" }
    } else { Log-Detail "Event26: Original gone - checking Sysmon archive" }
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
    if ($ev29_tgt -and (Test-Path $ev29_tgt)) {
        try {
            $fh = (Get-FileHash $ev29_tgt -Algorithm SHA256).Hash.ToUpper()
            Log-Detail "Event29 file=$fh IOC=$IOCvalue"
            if ($fh -eq $IOCvalue) {
                Log-Detail "Event 29: HASH MATCH -> kill + delete"
                Start-DFIRBackground -EventType "Event29" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $ev29_tgt -ProcessImage $ev29_img -AgentName $agentName
                if ($ev29_img) { try { Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $ev29_img } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue; Log-Detail "Event29: Killed parent PID $($_.ProcessId)" } } catch { Log-Detail "Event29: Kill parent failed: $($_.Exception.Message)" } }
                try { Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $ev29_tgt } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue; Log-Detail "Event29: Killed target PID $($_.ProcessId)" } } catch { Log-Detail "Event29: Kill target failed: $($_.Exception.Message)" }
                Start-Sleep -Seconds 2
                try { Remove-Item $ev29_tgt -Force; Log-Detail "Event29: Deleted: $ev29_tgt" }
                catch { try { Add-Type -TypeDefinition "using System; using System.Runtime.InteropServices; public class FH29 { [DllImport(`"kernel32.dll`",SetLastError=true,CharSet=CharSet.Unicode)] public static extern bool MoveFileEx(string a,string b,int f); public const int D=4; }" -EA SilentlyContinue; if([FH29]::MoveFileEx($ev29_tgt,$null,[FH29]::D)){Log-Detail "Event29: Scheduled delete on reboot"}else{Log-Detail "Event29: MoveFileEx failed"} } catch { Log-Detail "Event29: Schedule failed: $($_.Exception.Message)" } }
            } else { Log-Detail "Event29: mismatch (file=$fh IOC=$IOCvalue)" }
        } catch { Log-Detail "Event29 error: $($_.Exception.Message)" }
    } else { Log-Detail "Event29: targetFile not found: $ev29_tgt" }
}

# 6. FIM
if ($IOCtype -eq "sha256" -and $filePath) {
    if (Test-Path $filePath) {
        try {
            $fh = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToUpper()
            if ($fh -eq $IOCvalue) {
                Log-Detail "FIM HASH MATCH -> kill + delete"
                Start-DFIRBackground -EventType "FIM" -IOCValue $IOCvalue -IOCType $IOCtype -AlertJson $inputJson -TargetFile $filePath -AgentName $agentName
                try { Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $filePath } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue; Log-Detail "FIM: Killed PID (ExecutablePath): $($_.ProcessId)" } } catch { Log-Detail "FIM: Kill by ExecutablePath failed: $($_.Exception.Message)" }
                try { Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*$filePath*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue; Log-Detail "FIM: Killed PID (CommandLine): $($_.ProcessId)" } } catch { Log-Detail "FIM: Kill by CommandLine failed: $($_.Exception.Message)" }
                Start-Sleep -Seconds 2
                try { Remove-Item $filePath -Force; Log-Detail "FIM: Deleted: $filePath" }
                catch { try { Start-Process "cmd.exe" -ArgumentList "/c del /f /q `"$filePath`"" -WindowStyle Hidden; Log-Detail "FIM: Scheduled delete via cmd: $filePath" } catch { Log-Detail "FIM: Delete failed: $($_.Exception.Message)" } }
            } else { Log-Detail "FIM: mismatch (file=$fh IOC=$IOCvalue)" }
        } catch { Log-Detail "FIM error: $($_.Exception.Message)" }
    } else { Log-Detail "FIM: File not found: $filePath" }
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
