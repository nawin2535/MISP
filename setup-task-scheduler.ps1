# ============================================================================

# setup-task-scheduler.ps1 (Client Version - Windows 10/11 Home + Pro)

# ============================================================================

#region Configuration
$TaskName   = "SSJMUK Cyber Update"
$BatchFile  = Join-Path $PSScriptRoot "run-ssjmuk-task.bat"
$WorkingDir = $PSScriptRoot
#endregion

#region Functions
function Write-ColorOutput {
param(
[string]$Message,
[string]$Color = "White"
)
Write-Host $Message -ForegroundColor $Color
}

function Test-AdminPrivileges {


$identity = [Security.Principal.WindowsIdentity]::GetCurrent()

$principal = New-Object Security.Principal.WindowsPrincipal($identity)

return $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)


}
#endregion

#region Start

Write-ColorOutput "========================================" Cyan
Write-ColorOutput "Task Scheduler Setup (Client Version)" Cyan
Write-ColorOutput "========================================" Cyan
Write-Host ""

# ---------------------------

# Require Admin

# ---------------------------

if (-not (Test-AdminPrivileges)) {


Write-ColorOutput "ERROR : Run PowerShell as Administrator" Red
exit 1


}

# ---------------------------

# Check Batch Exists

# ---------------------------

if (-not (Test-Path $BatchFile)) {


Write-ColorOutput "ERROR : Batch file not found" Red
Write-ColorOutput $BatchFile Yellow

exit 1


}

Write-ColorOutput "Batch file OK :" Green
Write-ColorOutput $BatchFile Green
Write-Host ""

# ---------------------------

# Remove Old Task

# ---------------------------

$Existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($Existing) {


Write-ColorOutput "Removing existing task..." Yellow

Unregister-ScheduledTask `
    -TaskName $TaskName `
    -Confirm:$false


}

try {


Write-ColorOutput "Creating Scheduled Task..." Yellow


# ---------------------------
# Action
# ---------------------------

$Argument = "/c `"$BatchFile`""

$Action = New-ScheduledTaskAction `
    -Execute "cmd.exe" `
    -Argument $Argument `
    -WorkingDirectory $WorkingDir


# ---------------------------
# Trigger Daily 10 AM
# ---------------------------

$Trigger = New-ScheduledTaskTrigger `
    -Daily `
    -At 10:00AM


# ---------------------------
# Settings
# ---------------------------

$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RunOnlyIfNetworkAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 5)


# ---------------------------
# Principal
# (Compatible Home/Pro)
# ---------------------------

$Principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Highest


# ---------------------------
# Register
# ---------------------------

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Principal $Principal `
    -Description "Daily Sysmon Config Update (GitHub Pull)" `
    -Force | Out-Null


Write-ColorOutput ""
Write-ColorOutput "SUCCESS : Task Created" Green


$info = Get-ScheduledTaskInfo -TaskName $TaskName

Write-ColorOutput "Next Run :" Cyan
Write-ColorOutput $info.NextRunTime Green


Write-ColorOutput ""
Write-ColorOutput "Setup Completed Successfully" Green


}
catch {


Write-ColorOutput "FAILED to create scheduled task" Red

if ($_.Exception) {

    Write-ColorOutput $_.Exception.Message Red
}

exit 1


}

#endregion
