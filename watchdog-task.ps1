# ============================================================================
# watchdog-task.ps1 - Self-Healing Task Checker
# ============================================================================
# รันตอน startup ตรวจสอบว่า SSJMUK Cyber Update task ยังอยู่ไหม
# ถ้าไม่อยู่ให้สร้างใหม่อัตโนมัติ
# ============================================================================

#region Configuration
$WatchTaskName  = "SSJMUK Cyber Update"
$SetupBat       = Join-Path $PSScriptRoot "setup-task-scheduler.bat"
$LogDir         = Join-Path $PSScriptRoot "logs"
$LogFile        = Join-Path $LogDir "watchdog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
#endregion

#region Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $msg = "[$ts] [$Level] $Message"
    Write-Host $msg -ForegroundColor $(
        switch ($Level) {
            "ERROR"   { "Red"    }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green"  }
            default   { "White"  }
        }
    )
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value $msg -ErrorAction SilentlyContinue
}
#endregion

#region Main
Write-Log "========================================"
Write-Log "Watchdog started"
Write-Log "Checking task: $WatchTaskName"

$task = Get-ScheduledTask -TaskName $WatchTaskName -ErrorAction SilentlyContinue

if ($task) {
    Write-Log "Task '$WatchTaskName' exists - Status: $($task.State)" "SUCCESS"
    Write-Log "No action needed"
    exit 0
}

# Task ไม่อยู่ → สร้างใหม่
Write-Log "Task '$WatchTaskName' NOT FOUND - recreating..." "WARNING"

if (-not (Test-Path $SetupBat)) {
    Write-Log "setup-task-scheduler.bat not found: $SetupBat" "ERROR"
    exit 1
}

try {
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c `"$SetupBat`"" `
        -WorkingDirectory $PSScriptRoot `
        -Wait -PassThru

    if ($proc.ExitCode -eq 0) {
        # ตรวจสอบอีกครั้งหลังสร้าง
        $verify = Get-ScheduledTask -TaskName $WatchTaskName -ErrorAction SilentlyContinue
        if ($verify) {
            Write-Log "Task '$WatchTaskName' recreated successfully" "SUCCESS"
        } else {
            Write-Log "Task still missing after recreate attempt" "ERROR"
            exit 1
        }
    } else {
        Write-Log "setup-task-scheduler.bat exited with code: $($proc.ExitCode)" "ERROR"
        exit 1
    }
} catch {
    Write-Log "Failed to run setup: $($_.Exception.Message)" "ERROR"
    exit 1
}

Write-Log "Watchdog completed"
exit 0
#endregion