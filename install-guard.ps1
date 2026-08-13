# ============================================================================
# install-guard.ps1 - Walk-in installer for Wazuh-anchored self-heal
# ============================================================================
# ลงครั้งเดียวตอน walk-in: แทรก local wodle เข้า ossec.conf + restart WazuhSvc
# idempotent (รันซ้ำได้ ไม่แทรกซ้ำ). ต้องรันเป็น Administrator
# NOTE: console message เป็นอังกฤษ (fleet convention: Thai อยู่ใน comment เท่านั้น
#       เพราะ ps1 เป็น UTF-8 no BOM -> PS5.1 อ่านไทยใน string ผิด codepage)
#
#   .\install-guard.ps1                 install self-heal only
#   .\install-guard.ps1 -RunUpdateNow   install + trigger one update run now
#                                        (walk-in เครื่องค้าง: ดัน script/agent ทันที)
# ============================================================================

param(
    [switch]$RunUpdateNow,
    [string]$AgentDir = "C:\Program Files (x86)\ossec-agent",
    [string]$Root     = "C:\install-sysmon"
)

$ErrorActionPreference = "Stop"
$Tag        = "ssjmuk-task-guard"
$OssecConf  = Join-Path $AgentDir "ossec.conf"
$GuardPs1   = Join-Path $Root "ssjmuk-task-guard.ps1"
$WodleXml   = Join-Path $Root "ssjmuk-guard-wodle.xml"
$RunBat     = Join-Path $Root "run-ssjmuk-task.bat"
$BackupSuffix = "_bck13aug2569"

function Info { param($m) Write-Host "[install-guard] $m" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "[install-guard] $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "[install-guard] $m" -ForegroundColor Yellow }
function Die  { param($m) Write-Host "[install-guard] ERROR: $m" -ForegroundColor Red; exit 1 }

# --- Require Admin ---
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "Run as Administrator"
}

# --- Pre-flight ---
if (-not (Test-Path $GuardPs1))  { Die "guard script not found: $GuardPs1" }
if (-not (Test-Path $OssecConf)) { Die "ossec.conf not found: $OssecConf (agent installed elsewhere? pass -AgentDir)" }

$svc = Get-Service -Name 'WazuhSvc','OssecSvc' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $svc) { Die "Wazuh agent service not found (WazuhSvc/OssecSvc)" }
Info "Wazuh service: $($svc.Name) ($($svc.Status))"

# --- Idempotent: skip if already embedded ---
$raw = Get-Content -Path $OssecConf -Raw
if ($raw -match [regex]::Escape($Tag)) {
    Ok "wodle '$Tag' already present in ossec.conf - skip insert"
} else {
    if (-not (Test-Path $WodleXml)) { Die "wodle block not found: $WodleXml" }

    # backup before edit (writable because elevated)
    $bak = "$OssecConf$BackupSuffix"
    if (-not (Test-Path $bak)) { Copy-Item $OssecConf $bak -Force; Info "backup -> $bak" }

    # เอาเฉพาะ element <wodle>...</wodle> จากไฟล์ reference (ตัด comment ออก)
    $wodleRaw = Get-Content -Path $WodleXml -Raw
    $mWodle = [regex]::Match($wodleRaw, '(?s)<wodle\b.*?</wodle>')
    if (-not $mWodle.Success) { Die "cannot extract <wodle> from $WodleXml" }
    $block = "`r`n  " + $mWodle.Value + "`r`n"

    # แทรกก่อน </ossec_config> ตัวสุดท้าย (agent รวมทุก block)
    $idx = $raw.LastIndexOf("</ossec_config>")
    if ($idx -lt 0) { Die "</ossec_config> not found in ossec.conf" }
    $new = $raw.Substring(0, $idx) + $block + $raw.Substring($idx)
    # เขียน UTF-8 ไม่มี BOM: BOM ต้นไฟล์ทำ Wazuh XML parser reject -> agent ไม่ start
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OssecConf, $new, $utf8NoBom)
    Ok "inserted wodle '$Tag' into ossec.conf"
}

# --- Restart agent to load wodle (run_on_start fires guard once) ---
Info "restart $($svc.Name) ..."
Restart-Service -Name $svc.Name -Force
Start-Sleep -Seconds 3
$svc2 = Get-Service -Name $svc.Name
if ($svc2.Status -ne 'Running') { Die "$($svc.Name) not Running after restart (status=$($svc2.Status))" }
Ok "$($svc.Name) Running"

# --- Optional: trigger update now (walk-in stuck machine) ---
if ($RunUpdateNow) {
    if (Test-Path $RunBat) {
        Info "triggering update now: $RunBat"
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$RunBat`"" -WorkingDirectory $Root
        Ok "update triggered (background - see logs\ + Discord)"
    } else {
        Warn "run bat not found: $RunBat - skip -RunUpdateNow"
    }
}

Ok "install-guard done. self-heal active (interval 6h + run_on_start)"
