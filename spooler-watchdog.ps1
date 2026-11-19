<#
spooler-watchdog.ps1 - ตรวจ/กู้ Print Spooler ที่ค้าง (เรียกจาก ssjmuk-task.ps1 Step 10 ; task รันเป็น SYSTEM)

repo นี้เป็น public: ไฟล์นี้ไม่มีรหัส / IP / รายชื่อเครื่อง
อาการที่แก้ (เคส 19 พ.ย. 2569): spoolsv ยังรันแต่ไม่ตอบ -> printer หายจาก Settings, Excel ค้างตอนเปิด
  ; Fast Startup ทำให้ spoolsv ตัวที่ค้างอยู่รอดข้ามการ Shut down -> user เปิดเครื่องมาก็ยังค้าง
  ; Restart-Service ใช้ไม่ได้ตอนค้าง (SCM ส่ง stop แล้วรอ 30 วิ = event 7011/7046) -> kill process แล้ว start ใหม่

โหมด:
  -Install    : ลง/อัปเดต scheduled task + event source แล้วพิมพ์ SUMMARY (สถานะ + สถิติ 24 ชม.) ให้การ์ด Discord
  -Uninstall  : ถอด task (rollback ทั้งฟลีต = ตั้ง $SpoolerWatchdogMode = "uninstall" ใน ssjmuk-task.ps1)
  -Probe      : task เรียก (logon / ตื่นจาก sleep / ทุก 30 นาที) ตรวจแล้วกู้ หรือบันทึกอย่างเดียว ตาม ramp
  -Check      : ตรวจอย่างเดียว ไม่แก้เครื่อง ไม่เขียน event (ไม่ต้อง admin)
ramp: $EnforceAll = $false -> กู้จริงเฉพาะเครื่องที่ System log มี Spooler ค้าง/crash ใน $HistoryDays วัน
  เครื่องอื่นบันทึก event 4100 อย่างเดียว ; ขั้นถัดไปเปลี่ยน $EnforceAll = $true
event (Application, source SSJMUK-SpoolerWatchdog):
  4100 Warning ค้าง (log-only) / 4101 Warning ค้างแล้วกู้สำเร็จ / 4102 Error กู้ไม่สำเร็จ (Wazuh 60602 level 9)
  / 4103 Warning ค้างแต่ restart เกินโควตา / 4104 Information spooler หยุดอยู่ -> start ให้
output เป็นภาษาอังกฤษ: ssjmuk-task อ่าน stdout ของ process ลูกด้วย codepage ของเครื่อง ภาษาไทยจะเพี้ยน
exit: 0 = OK / SKIP / กู้สำเร็จ ; 1 = ค้างแต่ไม่ได้กู้ หรือกู้ไม่สำเร็จ ; 100 = error ภายใน (ข้อความขึ้นต้น FAIL)
#>
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Probe,
    [switch]$Check,
    [int]$ProbeTimeoutSec = 60
)

$ErrorActionPreference = 'Stop'
$TaskName           = 'SSJMUK Spooler Watchdog'
$TaskVersion        = 'v1 2026-11-19'
$EventSource        = 'SSJMUK-SpoolerWatchdog'
$StatePath          = 'HKLM:\SOFTWARE\SSJMUK\SpoolerWatchdog'
$LogPath            = Join-Path $PSScriptRoot 'logs\spooler-watchdog.log'
$EnforceAll         = $false
$HistoryDays        = 30
# kill ซ้ำไม่จบถ้าค้างทันทีหลัง start -> หยุดที่ 3 ครั้ง / 6 ชม. แล้วปล่อยให้ event 4103 บอกคน
$MaxRestarts        = 3
$RestartWindowHours = 6
$IntervalMin        = 30
$HistoryIds         = 7011, 7031, 7034, 7046
$Inv                = [Globalization.CultureInfo]::InvariantCulture

function Write-WdLog([string]$Msg) {
    try {
        $dir = Split-Path $LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt 512KB) { Move-Item $LogPath "$LogPath.1" -Force }
        Add-Content -Path $LogPath -Value ('[{0}] {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', $Inv), $Msg) -Encoding UTF8
    } catch { }
}

function Write-WdEvent([int]$Id, [string]$Type, [string]$Msg) {
    Write-WdLog "event $Id $Type $Msg"
    try { Write-EventLog -LogName Application -Source $EventSource -EventId $Id -EntryType $Type -Message $Msg } catch { }
}

function Get-SpoolerState {
    $svc = Get-CimInstance Win32_Service -Filter "Name='Spooler'"
    if (-not $svc) { return $null }
    $started = $null
    if ($svc.ProcessId) {
        try { $started = (Get-Process -Id $svc.ProcessId -ErrorAction Stop).StartTime.ToString('yyyy-MM-dd HH:mm', $Inv) } catch { }
    }
    [pscustomobject]@{ State = $svc.State; StartMode = $svc.StartMode; ProcessId = [int]$svc.ProcessId; Started = $started }
}

# ถามรายชื่อ printer ใน runspace แยก + timeout: spooler ค้าง = call ค้างตาม (Get-Printer ค้าง > 2 นาที 19 พ.ย.)
# ไม่ใช้ process ลูก: powershell เปิด powershell ติด Wazuh 92027 (L4) ทุกรอบ = หลายพัน alert/วันทั้งฟลีต
# runspace ที่ค้างไม่ Stop/Dispose (จะรอ call ใน native ค้างตาม) ; คลายเองเมื่อ spoolsv ถูก kill (RPC คืน error)
# ; จบ process ด้วย [Environment]::Exit ไม่ต้องรอ thread ที่ค้าง
# SYSTEM ไม่มี printer connection ของ user -> ได้เฉพาะ printer ในเครื่อง ไม่ไปแตะ print server ที่อาจอยู่นอกเครือข่าย
function Invoke-SpoolerProbe([int]$TimeoutSec, [scriptblock]$Body = $null) {
    if (-not $Body) { $Body = { Add-Type -AssemblyName System.Drawing; [System.Drawing.Printing.PrinterSettings]::InstalledPrinters.Count } }
    $ps = [powershell]::Create()
    [void]$ps.AddScript($Body.ToString())
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $h = $ps.BeginInvoke()
    if (-not $h.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)) {
        return [pscustomobject]@{ Ok = $false; Hung = $true; Seconds = [int]$sw.Elapsed.TotalSeconds; Detail = "no answer in $TimeoutSec s" }
    }
    $out = @(); $err1 = $null
    try {
        $out = @($ps.EndInvoke($h))
        if ($ps.Streams.Error.Count -gt 0) { $err1 = "$($ps.Streams.Error[0])" }
    } catch {
        $err1 = $_.Exception.Message
    } finally {
        $ps.Dispose()
    }
    $ok = (-not $err1 -and $out.Count -eq 1 -and "$($out[0])" -match '^\d+$')
    $detail = if ($ok) { "$($out[0]) printers" } elseif ($err1) { "error: $err1" } else { "unexpected output ($($out.Count))" }
    [pscustomobject]@{ Ok = $ok; Hung = $false; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Detail = $detail }
}

# ramp: event 7011/7046 เกิดเมื่อมีคนสั่ง stop/restart แล้ว spooler ไม่ตอบ ; 7031/7034 = crash
# ชื่อ service ใน message อาจเป็นชื่อแปลตามภาษาเครื่อง -> เทียบทั้ง 'Spooler' และ DisplayName
function Test-HangHistory {
    $names = @('Spooler')
    try { $names += (Get-Service Spooler -ErrorAction Stop).DisplayName } catch { }
    $pattern = ($names | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = $HistoryIds; StartTime = (Get-Date).AddDays(-$HistoryDays) } -ErrorAction SilentlyContinue
    @($ev | Where-Object { $_.Message -match $pattern }).Count -gt 0
}

function Get-WatchdogMode {
    if ($EnforceAll -or (Test-HangHistory)) { 'enforce' } else { 'log-only' }
}

function Select-RecentRestarts([string[]]$Values, [datetime]$Now) {
    $out = @()
    foreach ($v in $Values) {
        $t = [datetime]::MinValue
        if ([datetime]::TryParseExact($v, 'yyyy-MM-ddTHH:mm:ss', $Inv, [Globalization.DateTimeStyles]::None, [ref]$t) -and $t -gt $Now.AddHours(-$RestartWindowHours)) {
            $out += $v
        }
    }
    , $out
}

function Get-RecentRestarts {
    $vals = @()
    try { $vals = @((Get-ItemProperty -Path $StatePath -Name Restarts -ErrorAction Stop).Restarts) } catch { }
    Select-RecentRestarts $vals (Get-Date)
}

function Set-LastProbe {
    try {
        if (-not (Test-Path $StatePath)) { New-Item -Path $StatePath -Force | Out-Null }
        Set-ItemProperty -Path $StatePath -Name LastProbe -Value (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss', $Inv)
    } catch { }
}

function Get-LastProbeAgeMin {
    try {
        $v = (Get-ItemProperty -Path $StatePath -Name LastProbe -ErrorAction Stop).LastProbe
        [int]((Get-Date) - [datetime]::ParseExact($v, 'yyyy-MM-ddTHH:mm:ss', $Inv)).TotalMinutes
    } catch { -1 }
}

function Save-Restart([string[]]$Recent) {
    if (-not (Test-Path $StatePath)) { New-Item -Path $StatePath -Force | Out-Null }
    $list = [string[]](@($Recent) + (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss', $Inv))
    New-ItemProperty -Path $StatePath -Name Restarts -PropertyType MultiString -Value $list -Force | Out-Null
}

# endpoint ที่ spoolsv ค้างต่ออยู่ = เบาะแสหา port monitor ตัวการ (เช่น printer IP ที่ไม่อยู่ในวงตอนโน้ตบุ๊กอยู่นอก office)
function Get-SpoolerNetHint([int]$ProcId) {
    try {
        $c = @(Get-NetTCPConnection -OwningProcess $ProcId -ErrorAction Stop | Where-Object { $_.RemoteAddress -notin '0.0.0.0', '::', '127.0.0.1', '::1' })
        if ($c.Count -eq 0) { return 'tcp: none' }
        'tcp: ' + (($c | Select-Object -First 6 | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort) $($_.State)" }) -join ', ')
    } catch { 'tcp: n/a' }
}

# PrintIsolationHost = driver ที่รันแยก sandbox ผูกกับ spoolsv ตัวเก่า -> kill ด้วยกัน
# ไม่ลบ spool\PRINTERS: งานในคิวกลับมาพิมพ์ต่อหลัง start
function Restart-HungSpooler([int]$ProcId) {
    if ($ProcId -gt 0) { Stop-Process -Id $ProcId -Force -ErrorAction SilentlyContinue }
    Get-Process PrintIsolationHost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    # SCM recovery (RESTART หลัง 5 วิ) อาจ start ให้เองก่อน -> ดูสถานะก่อนค่อยสั่ง
    $deadline = (Get-Date).AddSeconds(45)
    do {
        Start-Sleep -Seconds 3
        $s = (Get-Service Spooler).Status
        if ($s -eq 'Running') { return $true }
        if ($s -eq 'Stopped') { try { Start-Service Spooler -ErrorAction Stop } catch { } }
    } while ((Get-Date) -lt $deadline)
    (Get-Service Spooler).Status -eq 'Running'
}

function Invoke-Watchdog([switch]$DryRun) {
    # ก่อน return ทุกทาง: เครื่องที่ตั้ง spooler เป็น Manual/Disabled ต้องไม่ขึ้น "never probed"
    if (-not $DryRun) { Set-LastProbe }
    $st = Get-SpoolerState
    if (-not $st) { return [pscustomobject]@{ Code = 0; Text = 'SKIP no Spooler service' } }
    # Disabled/Manual = admin ตั้งใจ (เช่นปิด spooler ลดช่องโหว่) ไม่ใช่งานของ watchdog
    if ($st.StartMode -ne 'Auto') { return [pscustomobject]@{ Code = 0; Text = "SKIP Spooler start mode $($st.StartMode)" } }
    $mode = Get-WatchdogMode

    if ($st.State -eq 'Stopped') {
        if ($DryRun) { return [pscustomobject]@{ Code = 1; Text = "STOPPED (check only) mode=$mode" } }
        if ($mode -ne 'enforce') {
            Write-WdEvent 4100 Warning 'Spooler is stopped (start mode Auto) - log-only, no action'
            return [pscustomobject]@{ Code = 1; Text = 'STOPPED log-only' }
        }
        try { Start-Service Spooler -ErrorAction Stop } catch { }
        $up = (Get-Service Spooler).Status -eq 'Running'
        if ($up) { Write-WdEvent 4104 Information 'Spooler was stopped (start mode Auto) - started'; return [pscustomobject]@{ Code = 0; Text = 'STARTED' } }
        Write-WdEvent 4102 Error 'Spooler is stopped (start mode Auto) and failed to start'
        return [pscustomobject]@{ Code = 1; Text = 'FAIL start' }
    }
    if ($st.State -ne 'Running') { return [pscustomobject]@{ Code = 0; Text = "SKIP Spooler state $($st.State)" } }

    $r1 = Invoke-SpoolerProbe $ProbeTimeoutSec
    if ($r1.Ok) { return [pscustomobject]@{ Code = 0; Text = "OK $($r1.Detail) in $($r1.Seconds)s mode=$mode" } }
    # spooler ตอบกลับเป็น error = ไม่ได้ค้าง ไม่แก้อะไร
    if (-not $r1.Hung) { return [pscustomobject]@{ Code = 0; Text = "WARN probe error ($($r1.Detail)) mode=$mode" } }
    # ช้าครั้งเดียว (เช่นช่วงบูตกำลังโหลด driver) ไม่นับ -> ต้องไม่ตอบ 2 รอบติด
    Start-Sleep -Seconds 10
    $r2 = Invoke-SpoolerProbe $ProbeTimeoutSec
    if (-not $r2.Hung) { return [pscustomobject]@{ Code = 0; Text = "OK slow (first probe no answer, then $($r2.Detail)) mode=$mode" } }

    $info = "no answer to 2 probes x $ProbeTimeoutSec s; spoolsv pid $($st.ProcessId) started $($st.Started); $(Get-SpoolerNetHint $st.ProcessId)"
    if ($DryRun) { return [pscustomobject]@{ Code = 1; Text = "HUNG (check only) mode=$mode $info" } }
    if ($mode -ne 'enforce') {
        Write-WdEvent 4100 Warning "Spooler HUNG - log-only (no hang history in $HistoryDays days): $info"
        return [pscustomobject]@{ Code = 1; Text = 'HUNG log-only' }
    }
    $recent = Get-RecentRestarts
    if ($recent.Count -ge $MaxRestarts) {
        Write-WdEvent 4103 Warning "Spooler HUNG but $($recent.Count) restarts in $RestartWindowHours h - no action: $info"
        return [pscustomobject]@{ Code = 1; Text = 'HUNG capped' }
    }
    Save-Restart $recent
    $up = Restart-HungSpooler $st.ProcessId
    $r3 = $null
    if ($up) { $r3 = Invoke-SpoolerProbe $ProbeTimeoutSec }
    if ($up -and $r3.Ok) {
        Write-WdEvent 4101 Warning "Spooler HUNG -> restarted, probe OK ($($r3.Detail)): $info"
        return [pscustomobject]@{ Code = 0; Text = 'RECOVERED' }
    }
    $why = if (-not $up) { 'service not running after restart' } else { "probe after restart: $($r3.Detail)" }
    Write-WdEvent 4102 Error "Spooler HUNG -> restart failed ($why): $info"
    [pscustomobject]@{ Code = 1; Text = "FAIL recover ($why)" }
}

# ไม่ใช้ trigger ตอน startup: Fast Startup (boot type 0x1) ไม่ยิง trigger นี้ -> ใช้ logon + ตื่นจาก sleep + ทุก 30 นาที
# daily + repetition 23:59 แทน -Once แบบไม่มีกำหนด (RepetitionDuration ไม่จำกัดใช้ไม่ได้ทุก build)
function New-WatchdogTaskParts([string]$ScriptFile) {
    $action = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptFile`" -Probe"
    $logon = New-ScheduledTaskTrigger -AtLogOn
    $logon.Delay = 'PT2M'
    $evClass = Get-CimClass -Namespace 'Root/Microsoft/Windows/TaskScheduler' -ClassName MSFT_TaskEventTrigger
    $resume = New-CimInstance -CimClass $evClass -ClientOnly
    $resume.Enabled = $true
    $resume.Delay = 'PT2M'
    $resume.Subscription = '<QueryList><Query Id="0" Path="System"><Select Path="System">' +
        '*[System[Provider[@Name=''Microsoft-Windows-Power-Troubleshooter''] and EventID=1]]</Select></Query></QueryList>'
    $every = New-ScheduledTaskTrigger -Daily -At '00:00'
    $every.Repetition = (New-ScheduledTaskTrigger -Once -At '00:00' -RepetitionInterval (New-TimeSpan -Minutes $IntervalMin) `
        -RepetitionDuration (New-TimeSpan -Hours 23 -Minutes 59)).Repetition
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    @{ Action = $action; Trigger = @($logon, $resume, $every); Settings = $settings; Principal = $principal
       Description = "SSJMUK Print Spooler watchdog $TaskVersion" }
}

function Get-WatchdogStats {
    $c = @{ 4100 = 0; 4101 = 0; 4102 = 0; 4103 = 0; 4104 = 0 }
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $EventSource; StartTime = (Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue
    foreach ($e in @($ev)) { if ($e -and $c.ContainsKey($e.Id)) { $c[$e.Id]++ } }
    $c
}

# last-probe=never บน task เดิม (ไม่ใช่เพิ่งลง) = task ไม่เคยรันจริง -> watchdog ล้มเงียบ ต้องขึ้น WARN
function Format-Summary([string]$TaskStatus, [string]$Mode, [hashtable]$Stats, [int]$ProbeAgeMin) {
    $lp = if ($ProbeAgeMin -lt 0) { 'never' } else { "$($ProbeAgeMin)m" }
    $s = "SUMMARY task $TaskStatus mode=$Mode last-probe=$lp 24h: hung-logonly=$($Stats[4100]) recovered=$($Stats[4101]) failed=$($Stats[4102]) capped=$($Stats[4103]) started=$($Stats[4104])"
    if (($Stats[4100] + $Stats[4101] + $Stats[4102] + $Stats[4103]) -gt 0) { $s += ' - WARN spooler hang in 24h' }
    elseif ($TaskStatus -eq 'ok' -and $ProbeAgeMin -lt 0) { $s += ' - WARN task never probed' }
    $s
}

function Install-Watchdog {
    if (-not [Diagnostics.EventLog]::SourceExists($EventSource)) { New-EventLog -LogName Application -Source $EventSource }
    $parts = New-WatchdogTaskParts $PSCommandPath
    $cur = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $status = 'ok'
    $sameDef = $cur -and $cur.Description -eq $parts.Description -and "$($cur.Actions[0].Arguments)" -eq $parts.Action.Arguments
    if (-not $sameDef) {
        Register-ScheduledTask -TaskName $TaskName -Action $parts.Action -Trigger $parts.Trigger -Settings $parts.Settings `
            -Principal $parts.Principal -Description $parts.Description -Force | Out-Null
        $status = if ($cur) { 'updated' } else { 'installed' }
        Write-WdLog "task $status ($TaskVersion)"
    } elseif ($cur.State -eq 'Disabled') {
        # admin ปิดเองที่เครื่อง = ตั้งใจ ไม่เปิดคืน ; ขึ้น WARN ให้เห็นในการ์ด
        $status = 'disabled-locally WARN'
    }
    Format-Summary $status (Get-WatchdogMode) (Get-WatchdogStats) (Get-LastProbeAgeMin)
}

function Uninstall-Watchdog {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-WdLog 'task removed'
        return 'SUMMARY task removed'
    }
    'SUMMARY task not present'
}

if (-not ($Install -or $Uninstall -or $Probe -or $Check)) { return }

$exitCode = 0
try {
    if ($Install) {
        Write-Output (Install-Watchdog)
    } elseif ($Uninstall) {
        Write-Output (Uninstall-Watchdog)
    } else {
        $r = Invoke-Watchdog -DryRun:$Check
        if (-not $Check -and $r.Text -notmatch '^(OK \d|SKIP)') { Write-WdLog "probe: $($r.Text)" }
        Write-Output $r.Text
        $exitCode = $r.Code
    }
} catch {
    $msg = "FAIL $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    Write-WdLog $msg
    Write-Output $msg
    $exitCode = 100
}
# runspace ของ probe ที่ค้าง (log-only / -Check) ทำให้ exit ปกติรอไม่จบ -> ปิด process ตรง
[Console]::Out.Flush()
[Environment]::Exit($exitCode)
# EOF-SENTINEL-SSJMUK
