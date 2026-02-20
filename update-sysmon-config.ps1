# ============================================================================
# update-sysmon-config.ps1 - Update Sysmon Configuration
# ============================================================================
# Description: Downloads and applies the latest Sysmon configuration from GitHub
#              Note: Execution policy is handled by the calling script
# ============================================================================

#region Configuration
$ConfigUrl = "https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main/sysmonconfig-export-v2.xml"
$TempDir = "C:\temp"
$LocalXml = Join-Path $TempDir "sysmonconfig-export-v2.xml"
$SysmonExe = "Sysmon.exe"
#endregion

#region Functions
function Test-SysmonInstalled {
    try {
        $SysmonPath = Get-Command $SysmonExe -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Test-AdminPrivileges {
    $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
#endregion

#region Main Execution
try {
    # Check if Sysmon is installed
    if (-not (Test-SysmonInstalled)) {
        Write-Output "ERROR: Sysmon.exe not found in PATH. Please ensure Sysmon is installed."
        exit 1
    }
    
    # Check admin privileges (Sysmon config updates may require admin)
    if (-not (Test-AdminPrivileges)) {
        Write-Output "WARNING: Script is not running with administrator privileges."
        Write-Output "Sysmon configuration update may fail without admin rights."
    }
    
    # Create temp directory if it doesn't exist
    if (-not (Test-Path $TempDir)) {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
        Write-Output "Created temp directory: $TempDir"
    }
    
    # Download latest configuration
    Write-Output "Downloading latest Sysmon configuration from: $ConfigUrl"
    try {
        $ProgressPreference = 'SilentlyContinue' # Suppress progress bar for cleaner output
        Invoke-WebRequest -Uri $ConfigUrl -OutFile $LocalXml -UseBasicParsing -ErrorAction Stop
        
        if (Test-Path $LocalXml) {
            $FileSize = (Get-Item $LocalXml).Length
            Write-Output "Successfully downloaded configuration file ($([math]::Round($FileSize/1KB, 2)) KB)"
        } else {
            Write-Output "ERROR: Download completed but file not found at: $LocalXml"
            exit 1
        }
    } catch {
        Write-Output "ERROR: Failed to download configuration: $_"
        Write-Output "Exception: $($_.Exception.Message)"
        exit 1
    }
    
    # Apply configuration
    Write-Output "Applying Sysmon configuration..."
    try {
        $ApplyResult = & $SysmonExe -c $LocalXml 2>&1
        $ExitCode = $LASTEXITCODE
        
        if ($ApplyResult) {
            Write-Output $ApplyResult
        }
        
        if ($ExitCode -eq 0) {
            Write-Output "Configuration applied successfully"
        } else {
            Write-Output "WARNING: Sysmon returned exit code: $ExitCode"
            Write-Output "Configuration may not have been applied correctly"
        }
    } catch {
        Write-Output "ERROR: Failed to apply configuration: $_"
        Write-Output "Exception: $($_.Exception.Message)"
        exit 1
    }
    
    # Verify configuration (check for PDF extension as a test)
    Write-Output "Verifying configuration..."
    try {
        $VerifyResult = & $SysmonExe -c 2>&1 | Select-String -Pattern "pdf" -CaseSensitive:$false
        
        if ($VerifyResult) {
            Write-Output "SUCCESS: Configuration verified - PDF extension found in config"
            Write-Output "Config preview: $($VerifyResult -join ', ')"
        } else {
            Write-Output "WARNING: Could not verify PDF extension in configuration"
        }
    } catch {
        Write-Output "WARNING: Could not verify configuration: $_"
    }
    
    Write-Output "Sysmon configuration update completed successfully"
    exit 0
    
} catch {
    Write-Output "FATAL ERROR: $_"
    Write-Output "Exception: $($_.Exception.Message)"
    Write-Output "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
#endregion
