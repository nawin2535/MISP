# ============================================================================
# ssjmuk-task.ps1 - Main Task Scheduler Script
# ============================================================================
# Description: Main script that orchestrates Sysmon configuration updates
#              Designed to run daily at 10:00 AM via Windows Task Scheduler
#              Includes detailed logging and retry mechanism for failures
# ============================================================================

#region Configuration
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir = Join-Path $ScriptPath "logs"
$LogFile = Join-Path $LogDir "ssjmuk-task_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$MaxRetries = 5
$RetryDelaySeconds = 60

# GitHub Configuration - All scripts are downloaded from here
$GitHubBaseUrl = "https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main"

# Scripts to download from GitHub before execution
$ScriptsToDownload = @(
    @{
        Name = "update-sysmon-config"
        GitHubPath = "update-sysmon-config.ps1"
        LocalPath = Join-Path $ScriptPath "update-sysmon-config.ps1"
        Required = $true
    }
    # Add more scripts here in the future
    # @{
    #     Name = "another-script"
    #     GitHubPath = "another-script.ps1"
    #     LocalPath = Join-Path $ScriptPath "another-script.ps1"
    #     Required = $false
    # }
)

# Scripts to run (after downloading)
$ScriptsToRun = @(
    @{
        Name = "update-sysmon-config"
        Path = Join-Path $ScriptPath "update-sysmon-config.ps1"
        Required = $true
    }
    # Add more scripts here in the future
    # @{
    #     Name = "another-script"
    #     Path = Join-Path $ScriptPath "another-script.ps1"
    #     Required = $false
    # }
)
#endregion

#region Functions
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to console
    $ColorMap = @{
        "INFO" = "White"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
        "SUCCESS" = "Green"
    }
    Write-Host $LogMessage -ForegroundColor $ColorMap[$Level]
    
    # Write to log file
    try {
        Add-Content -Path $LogFile -Value $LogMessage -ErrorAction SilentlyContinue
    } catch {
        # If logging fails, at least try to write to console
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }
}

function Test-InternetConnection {
    param(
        [int]$TimeoutSeconds = 5
    )
    
    try {
        $TestUrl = "https://www.google.com"
        $Response = Invoke-WebRequest -Uri $TestUrl -Method Head -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop
        return $true
    } catch {
        Write-Log "Internet connection test failed: $_" "WARNING"
        return $false
    }
}

function Invoke-ScriptWithRetry {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath,
        [Parameter(Mandatory=$true)]
        [string]$ScriptName,
        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 5,
        [Parameter(Mandatory=$false)]
        [int]$RetryDelaySeconds = 60
    )
    
    $Attempt = 0
    $Success = $false
    
    while ($Attempt -lt $MaxRetries -and -not $Success) {
        $Attempt++
        Write-Log "Attempting to run script: $ScriptName (Attempt $Attempt/$MaxRetries)" "INFO"
        
        # Check if script file exists
        if (-not (Test-Path $ScriptPath)) {
            Write-Log "Script file not found: $ScriptPath" "ERROR"
            return $false
        }
        
        # Check internet connection before running (for scripts that need it)
        if ($ScriptName -like "*update*" -or $ScriptName -like "*download*") {
            if (-not (Test-InternetConnection)) {
                Write-Log "No internet connection detected. Waiting $RetryDelaySeconds seconds before retry..." "WARNING"
                if ($Attempt -lt $MaxRetries) {
                    Start-Sleep -Seconds $RetryDelaySeconds
                    continue
                } else {
                    Write-Log "Max retries reached. Internet connection still unavailable." "ERROR"
                    return $false
                }
            }
        }
        
        try {
            # Temporarily set execution policy for this session
            $OriginalPolicy = Get-ExecutionPolicy -Scope Process
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
            
            Write-Log "Executing: $ScriptPath" "INFO"
            
            # Run the script and capture output
            $Output = & $ScriptPath 2>&1
            $ExitCode = $LASTEXITCODE
            
            # Restore original execution policy
            Set-ExecutionPolicy -ExecutionPolicy $OriginalPolicy -Scope Process -Force -ErrorAction SilentlyContinue
            
            if ($Output) {
                foreach ($Line in $Output) {
                    Write-Log "  [$ScriptName] $Line" "INFO"
                }
            }
            
            if ($ExitCode -eq 0 -or $null -eq $ExitCode) {
                Write-Log "Script '$ScriptName' completed successfully" "SUCCESS"
                $Success = $true
            } else {
                Write-Log "Script '$ScriptName' exited with code: $ExitCode" "ERROR"
                if ($Attempt -lt $MaxRetries) {
                    Write-Log "Waiting $RetryDelaySeconds seconds before retry..." "WARNING"
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
            }
        } catch {
            Write-Log "Error executing script '$ScriptName': $_" "ERROR"
            Write-Log "Exception details: $($_.Exception.Message)" "ERROR"
            Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
            
            if ($Attempt -lt $MaxRetries) {
                Write-Log "Waiting $RetryDelaySeconds seconds before retry..." "WARNING"
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }
    }
    
    if (-not $Success) {
        Write-Log "Failed to execute script '$ScriptName' after $MaxRetries attempts" "ERROR"
    }
    
    return $Success
}

function Initialize-Logging {
    # Create logs directory if it doesn't exist
    if (-not (Test-Path $LogDir)) {
        try {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
            Write-Log "Created log directory: $LogDir" "INFO"
        } catch {
            Write-Host "Failed to create log directory: $_" -ForegroundColor Red
            # Fallback to script directory
            $script:LogFile = Join-Path $ScriptPath "ssjmuk-task_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        }
    }
    
    Write-Log "========================================" "INFO"
    Write-Log "Task started: ssjmuk-task.ps1" "INFO"
    Write-Log "Script path: $ScriptPath" "INFO"
    Write-Log "Log file: $LogFile" "INFO"
    Write-Log "========================================" "INFO"
}

function Cleanup-OldLogs {
    param(
        [int]$DaysToKeep = 30
    )
    
    try {
        $CutoffDate = (Get-Date).AddDays(-$DaysToKeep)
        $OldLogs = Get-ChildItem -Path $LogDir -Filter "ssjmuk-task_*.log" | Where-Object { $_.LastWriteTime -lt $CutoffDate }
        
        if ($OldLogs) {
            $Count = ($OldLogs | Measure-Object).Count
            $OldLogs | Remove-Item -Force
            Write-Log "Cleaned up $Count old log file(s) (older than $DaysToKeep days)" "INFO"
        }
    } catch {
        Write-Log "Failed to cleanup old logs: $_" "WARNING"
    }
}

function Download-ScriptFromGitHub {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GitHubUrl,
        [Parameter(Mandatory=$true)]
        [string]$LocalPath,
        [Parameter(Mandatory=$true)]
        [string]$ScriptName,
        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 5,
        [Parameter(Mandatory=$false)]
        [int]$RetryDelaySeconds = 10
    )
    
    $Attempt = 0
    $Success = $false
    
    while ($Attempt -lt $MaxRetries -and -not $Success) {
        $Attempt++
        Write-Log "Downloading '$ScriptName' from GitHub (Attempt $Attempt/$MaxRetries)..." "INFO"
        
        try {
            # Check internet connection first
            if (-not (Test-InternetConnection)) {
                Write-Log "No internet connection detected. Waiting $RetryDelaySeconds seconds before retry..." "WARNING"
                if ($Attempt -lt $MaxRetries) {
                    Start-Sleep -Seconds $RetryDelaySeconds
                    continue
                } else {
                    Write-Log "Max retries reached. Internet connection still unavailable." "ERROR"
                    return $false
                }
            }
            
            # Download the script
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $GitHubUrl -OutFile $LocalPath -UseBasicParsing -ErrorAction Stop
            
            # Verify file was downloaded
            if (Test-Path $LocalPath) {
                $FileSize = (Get-Item $LocalPath).Length
                Write-Log "Successfully downloaded '$ScriptName' ($([math]::Round($FileSize/1KB, 2)) KB)" "SUCCESS"
                $Success = $true
            } else {
                Write-Log "Download completed but file not found at: $LocalPath" "ERROR"
                if ($Attempt -lt $MaxRetries) {
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
            }
        } catch {
            Write-Log "Failed to download '$ScriptName': $_" "ERROR"
            Write-Log "Exception: $($_.Exception.Message)" "ERROR"
            
            if ($Attempt -lt $MaxRetries) {
                Write-Log "Waiting $RetryDelaySeconds seconds before retry..." "WARNING"
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }
    }
    
    if (-not $Success) {
        Write-Log "Failed to download '$ScriptName' after $MaxRetries attempts" "ERROR"
    }
    
    return $Success
}

function Download-AllScripts {
    Write-Log "========================================" "INFO"
    Write-Log "Downloading scripts from GitHub..." "INFO"
    Write-Log "========================================" "INFO"
    
    $DownloadResults = @()
    $AllRequiredDownloaded = $true
    
    foreach ($Script in $ScriptsToDownload) {
        $GitHubUrl = "$GitHubBaseUrl/$($Script.GitHubPath)"
        
        Write-Log "----------------------------------------" "INFO"
        Write-Log "Downloading: $($Script.Name)" "INFO"
        Write-Log "  From: $GitHubUrl" "INFO"
        Write-Log "  To: $($Script.LocalPath)" "INFO"
        Write-Log "----------------------------------------" "INFO"
        
        $Result = Download-ScriptFromGitHub `
            -GitHubUrl $GitHubUrl `
            -LocalPath $Script.LocalPath `
            -ScriptName $Script.Name `
            -MaxRetries $MaxRetries `
            -RetryDelaySeconds $RetryDelaySeconds
        
        $DownloadResults += @{
            Name = $Script.Name
            Success = $Result
            Required = $Script.Required
        }
        
        if (-not $Result -and $Script.Required) {
            $AllRequiredDownloaded = $false
            Write-Log "Required script '$($Script.Name)' download failed!" "ERROR"
        } elseif (-not $Result) {
            Write-Log "Optional script '$($Script.Name)' download failed (non-critical)" "WARNING"
        }
    }
    
    Write-Log "========================================" "INFO"
    Write-Log "Download Summary:" "INFO"
    foreach ($Result in $DownloadResults) {
        $Status = if ($Result.Success) { "SUCCESS" } else { "FAILED" }
        $Required = if ($Result.Required) { "(Required)" } else { "(Optional)" }
        Write-Log "  $($Result.Name): $Status $Required" $Status
    }
    Write-Log "========================================" "INFO"
    
    return $AllRequiredDownloaded
}
#endregion

#region Main Execution
try {
    # Initialize logging
    Initialize-Logging
    
    # Cleanup old logs
    Cleanup-OldLogs
    
    # Display system information
    Write-Log "System Information:" "INFO"
    Write-Log "  Computer Name: $env:COMPUTERNAME" "INFO"
    Write-Log "  User: $env:USERNAME" "INFO"
    Write-Log "  PowerShell Version: $($PSVersionTable.PSVersion)" "INFO"
    Write-Log "  Execution Policy (Process): $(Get-ExecutionPolicy -Scope Process)" "INFO"
    Write-Log "  Execution Policy (CurrentUser): $(Get-ExecutionPolicy -Scope CurrentUser)" "INFO"
    Write-Log "  GitHub Base URL: $GitHubBaseUrl" "INFO"
    
    # Download all scripts from GitHub first
    $AllScriptsDownloaded = Download-AllScripts
    
    if (-not $AllScriptsDownloaded) {
        Write-Log "One or more required scripts failed to download. Aborting execution." "ERROR"
        Write-Log "Please check your internet connection and GitHub accessibility." "ERROR"
        exit 1
    }
    
    # Track overall success
    $OverallSuccess = $true
    $ScriptResults = @()
    
    # Run each configured script
    foreach ($Script in $ScriptsToRun) {
        Write-Log "----------------------------------------" "INFO"
        Write-Log "Processing script: $($Script.Name)" "INFO"
        Write-Log "----------------------------------------" "INFO"
        
        $Result = Invoke-ScriptWithRetry `
            -ScriptPath $Script.Path `
            -ScriptName $Script.Name `
            -MaxRetries $MaxRetries `
            -RetryDelaySeconds $RetryDelaySeconds
        
        $ScriptResults += @{
            Name = $Script.Name
            Success = $Result
            Required = $Script.Required
        }
        
        if (-not $Result -and $Script.Required) {
            $OverallSuccess = $false
            Write-Log "Required script '$($Script.Name)' failed!" "ERROR"
        } elseif (-not $Result) {
            Write-Log "Optional script '$($Script.Name)' failed (non-critical)" "WARNING"
        }
    }
    
    # Summary
    Write-Log "========================================" "INFO"
    Write-Log "Task Summary:" "INFO"
    foreach ($Result in $ScriptResults) {
        $Status = if ($Result.Success) { "SUCCESS" } else { "FAILED" }
        $Required = if ($Result.Required) { "(Required)" } else { "(Optional)" }
        Write-Log "  $($Result.Name): $Status $Required" $Status
    }
    
    if ($OverallSuccess) {
        Write-Log "All required tasks completed successfully!" "SUCCESS"
        Write-Log "========================================" "INFO"
        exit 0
    } else {
        Write-Log "One or more required tasks failed!" "ERROR"
        Write-Log "========================================" "INFO"
        exit 1
    }
    
} catch {
    Write-Log "Fatal error in main execution: $_" "ERROR"
    Write-Log "Exception: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    Write-Log "========================================" "INFO"
    exit 1
} finally {
    Write-Log "Task completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Log "Log file saved to: $LogFile" "INFO"
}
#endregion
