# ============================================================================
# update-sysmon-config.ps1 - Update Sysmon Configuration
# ============================================================================
# Description: Downloads and applies the latest Sysmon configuration from GitHub
#              Note: Execution policy is handled by the calling script
# ============================================================================

#region Configuration
# FileServer primary (HTTP internal, เปิดตลอด) -> GitHub fallback (firewall เปิด ~10:00 เท่านั้น)
# ที่ผ่านมา GitHub-only ทำ task ที่รันก่อน 10:00 fail เพราะ GitHub ถูก block ตอนนั้น
$XmlRelPath     = "sysmonconfig-export-v2.xml"
$FileServerBase = "http://cyberupdate-mdo.moph.go.th:19080"
$GitHubBase     = "https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main"
$ConfigSources  = @(
    @{ Name = "FileServer"; Url = "$FileServerBase/$XmlRelPath" },
    @{ Name = "GitHub";     Url = "$GitHubBase/$XmlRelPath" }
)
$TempDir = "C:\temp"
$LocalXml = Join-Path $TempDir "sysmonconfig-export-v2.xml"
$SysmonExe = "Sysmon.exe"
$MinXmlBytes = 2000   # XML จริง ~180KB; ต่ำกว่านี้ = error page/truncated -> reject
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

function Test-SysmonXml {
    # ยืนยันไฟล์ที่โหลดมาเป็น Sysmon config จริง (กัน error page / truncated / rate-limit HTML)
    param([string]$Path, [int]$MinBytes = 2000)
    if (-not (Test-Path $Path)) { return $false }
    if ((Get-Item $Path).Length -lt $MinBytes) { return $false }
    $raw = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($raw)) { return $false }
    $head = $raw.Substring(0, [Math]::Min(512, $raw.Length))
    if ($head -match '(?i)<!DOCTYPE html|<html|Too Many Requests|Rate limit') { return $false }
    try { [void][xml]$raw } catch { return $false }   # ต้อง well-formed XML
    if ($raw -notmatch '(?i)<Sysmon') { return $false }  # ต้องมี root <Sysmon ...>
    return $true
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
    
    # Download latest configuration: FileServer primary -> GitHub fallback (+validate)
    $Downloaded = $false
    foreach ($src in $ConfigSources) {
        Write-Output "Downloading Sysmon configuration from $($src.Name): $($src.Url)"
        $Tmp = "$LocalXml.tmp"
        Remove-Item $Tmp -Force -ErrorAction SilentlyContinue
        try {
            $ProgressPreference = 'SilentlyContinue' # Suppress progress bar for cleaner output
            Invoke-WebRequest -Uri $src.Url -OutFile $Tmp -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        } catch {
            Write-Output "  $($src.Name) download failed: $($_.Exception.Message)"
            Remove-Item $Tmp -Force -ErrorAction SilentlyContinue
            continue
        }
        if (Test-SysmonXml -Path $Tmp -MinBytes $MinXmlBytes) {
            Move-Item $Tmp $LocalXml -Force
            $FileSize = (Get-Item $LocalXml).Length
            Write-Output "  Validated Sysmon config from $($src.Name) ($([math]::Round($FileSize/1KB, 2)) KB)"
            $Downloaded = $true
            break
        } else {
            Write-Output "  $($src.Name) content invalid (not well-formed Sysmon XML / too small) - trying next source"
            Remove-Item $Tmp -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $Downloaded) {
        Write-Output "ERROR: Could not obtain a valid Sysmon config from any source (FileServer/GitHub)"
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

# EOF-SENTINEL-SSJMUK
