# ============================================================================
# ssjmuk-task-guard.ps1 - Wazuh-anchored self-heal for "SSJMUK Cyber Update"
# ============================================================================
# เรียกโดย local wodle "command" ใน ossec.conf (รันเป็น SYSTEM = WazuhSvc)
# WazuhSvc รอด task deletion (scheduled task หาย แต่ agent ยัง active) จึงใช้เป็น
# anchor: เช็กว่า task หลักยังอยู่ไหม ไม่อยู่ = สร้างคืนผ่าน setup-task-scheduler.ps1
# stdout จะถูก wodle ส่งขึ้น manager -> ทำ rule จับ "RECREATED" เป็น alert ได้
# ============================================================================

$TaskName = "SSJMUK Cyber Update"
$Root     = Split-Path -Parent $MyInvocation.MyCommand.Path
$Setup    = Join-Path $Root "setup-task-scheduler.ps1"
$GuardLog = Join-Path $Root "logs\guard.log"

function Emit {
    param([string]$Msg)
    $line = "[{0}] ssjmuk-task-guard: {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Msg
    # stdout = ช่องทางหลักให้ wodle เก็บขึ้น manager; logfile = สำรอง/forensic ในเครื่อง
    Write-Output $line
    try {
        $ld = Split-Path -Parent $GuardLog
        if (-not (Test-Path $ld)) { New-Item -ItemType Directory -Path $ld -Force | Out-Null }
        Add-Content -Path $GuardLog -Value $line -ErrorAction SilentlyContinue
    } catch { }
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($task) {
    Emit "OK task present state=$($task.State)"
    exit 0
}

Emit "MISSING - recreating via setup"

if (-not (Test-Path $Setup)) {
    Emit "RECREATE_FAILED setup not found: $Setup"
    exit 1
}

try {
    & PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File $Setup | Out-Null
} catch {
    Emit "RECREATE_FAILED setup error: $($_.Exception.Message)"
    exit 1
}

$verify = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($verify) {
    Emit "RECREATED ok state=$($verify.State)"
    exit 0
} else {
    Emit "RECREATE_FAILED task still missing after setup"
    exit 1
}

# EOF-SENTINEL-SSJMUK
