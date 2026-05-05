# ============================================================================
# ssjmuk-task.ps1 - Main Task Scheduler Script
# ============================================================================
# Description: Main script that orchestrates Sysmon configuration updates
#              Designed to run daily at 10:00 AM via Windows Task Scheduler
#              Includes detailed logging, retry mechanism, and Discord notifications
# ============================================================================

#region Configuration
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir = Join-Path $ScriptPath "logs"
$LogFile = Join-Path $LogDir "ssjmuk-task_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$MaxRetries = 5
$RetryDelaySeconds = 60

# GitHub Configuration
$GitHubBaseUrl = "https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main"

# Discord Webhook
$DiscordWebhookUrl = "https://discord.com/api/webhooks/1485825229547901110/tGVBhaf47J26DYuWaxlaHvUzXF3iKop1TxqSCSFPUn_nEx-2iJTbMRctZfjgYrtMGaFY"

# Step 7: Wazuh Agent Upgrade Configuration
# แก้ไขค่านี้เมื่อต้องการ upgrade เป็น version ใหม่
$VersionWazuh  = "4.14.5"
$URL_Download  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi"

# Scripts to download from GitHub before execution
$ScriptsToDownload = @(
    @{
        Name       = "update-sysmon-config"
        GitHubPath = "update-sysmon-config.ps1"
        LocalPath  = Join-Path $ScriptPath "update-sysmon-config.ps1"
        Required   = $true
    }
)

# Scripts to run (after downloading)
$ScriptsToRun = @(
    @{
        Name     = "update-sysmon-config"
        Path     = Join-Path $ScriptPath "update-sysmon-config.ps1"
        Required = $true
    }
)
#endregion

#region Logging
# Buffer เก็บ log ทั้งหมดสำหรับส่ง Discord ตอนจบ
$script:LogBuffer = [System.Collections.Generic.List[string]]::new()

# Step 7: เก็บ version info สำหรับแสดงใน Discord summary
$script:WazuhVersionInfo = $null   # e.g. "4.14.4 → upgraded to 4.14.5" หรือ "4.14.5 (up-to-date)"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $Timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"

    $ColorMap = @{
        "INFO"    = "White"
        "WARNING" = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
    }
    Write-Host $LogMessage -ForegroundColor $ColorMap[$Level]

    try {
        Add-Content -Path $LogFile -Value $LogMessage -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }

    # เพิ่มเข้า buffer (เก็บเฉพาะ WARNING/ERROR/SUCCESS เพื่อไม่ให้ยาวเกิน)
    if ($Level -ne "INFO") {
        $script:LogBuffer.Add($LogMessage)
    }
}
#endregion

#region Discord
function Send-DiscordSummary {
    param(
        [Parameter(Mandatory=$true)]
        [bool]$OverallSuccess,
        [Parameter(Mandatory=$true)]
        [array]$Results
    )

    # Unicode escape - ไม่พึ่ง emoji literal ในไฟล์
    $iconOK   = [System.Char]::ConvertFromUtf32(0x2705)  # ✅
    $iconFail = [System.Char]::ConvertFromUtf32(0x274C)  # ❌

    $StatusText = if ($OverallSuccess) { "SUCCESS" } else { "ERROR" }
    $TitleIcon  = if ($OverallSuccess) { $iconOK } else { $iconFail }
    $Title      = if ($OverallSuccess) { "Task completed successfully" } else { "Task completed with errors" }

    # สร้าง summary lines
    $SummaryLines = $Results | ForEach-Object {
        $icon = if ($_.Success) { $iconOK } else { $iconFail }
        $req  = if ($_.Required) { "(Required)" } else { "(Optional)" }
        $line = "$icon $($_.Name) $req"
        # เพิ่ม version info สำหรับ Step 7
        if ($_.Name -eq "Step7-UpgradeWazuhAgent" -and $script:WazuhVersionInfo) {
            $line += " [$script:WazuhVersionInfo]"
        }
        $line
    }

    # เพิ่ม WARNING/ERROR/SUCCESS log (จำกัด 10 บรรทัด)
    $ImportantLogs = $script:LogBuffer | Select-Object -Last 10

    # ดึง IPv4 address จาก adapter ที่ Up และไม่ใช่ loopback
    <# $IPAddress = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -ne '127.0.0.1' } |
        Select-Object -First 1).IPAddress #>
    $IPAddress = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '192.168.*' -and ($_.InterfaceAlias -like 'wi*' -or $_.InterfaceAlias -like 'ether*') } | Select-Object -First 1).IPAddress
    if (-not $IPAddress) {
        # not use in org network
        $IPAddress = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -like 'wi*' } | Select-Object -First 1).IPAddress

        if (-not $IPAddress) {$IPAddress = "N/A" }
    
    }

    # ดึง Wazuh Agent Name จาก ossec.conf
    $OssecConf    = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf"
    $AgentName    = "N/A"
    if (Test-Path $OssecConf) {
        try {
            $ConfContent = Get-Content -Path $OssecConf -Raw -ErrorAction Stop
            if ($ConfContent -match '<agent_name>([^<]+)</agent_name>') {
                $AgentName = $Matches[1].Trim()
            }
        } catch {
            $AgentName = "N/A"
        }
    }

    $Fields = @(
        @{
            name   = "Computer"
            value  = "``$env:COMPUTERNAME``"
            inline = $true
        },
        @{
            name   = "IP Address"
            value  = "``$IPAddress``"
            inline = $true
        },
        @{
            name   = "User"
            value  = "``$env:USERNAME``"
            inline = $true
        },
        @{
            name   = "Agent Name"
            value  = "``$AgentName``"
            inline = $false
        },
        @{
            name   = "Time"
            value  = "``$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')``"
            inline = $false
        },
        @{
            name   = "Step Results"
            value  = ($SummaryLines -join "`n")
            inline = $false
        }
    )

    if ($ImportantLogs.Count -gt 0) {
        $logText = ($ImportantLogs -join "`n")
        if ($logText.Length -gt 1000) {
            $logText = $logText.Substring($logText.Length - 1000)
        }
        $Fields += @{
            name   = "Recent Warnings/Errors"
            value  = "``````$logText``````"
            inline = $false
        }
    }

    $ColorMap = @{
        "SUCCESS" = 3066993
        "ERROR"   = 15158332
    }

    $Payload = @{
        username = "SSJMUK Monitor"
        embeds   = @(
            @{
                title       = "$TitleIcon $Title"
                description = "Daily Sysmon Config Update Task Summary"
                color       = $ColorMap[$StatusText]
                fields      = $Fields
                footer      = @{ text = "SSJMUK Cyber Update Task" }
            }
        )
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-RestMethod `
            -Uri $DiscordWebhookUrl `
            -Method Post `
            -ContentType "application/json; charset=utf-8" `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($Payload)) `
            -ErrorAction Stop
        Write-Log "Discord summary sent" "INFO"
    } catch {
        Write-Log "Failed to send Discord summary: $($_.Exception.Message)" "WARNING"
    }
}
#endregion

#region Functions
function Test-InternetConnection {
    param([int]$TimeoutSeconds = 5)
    try {
        $Response = Invoke-WebRequest -Uri "https://www.google.com" -Method Head -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop
        return $true
    } catch {
        Write-Log "Internet connection test failed: $_" "WARNING"
        return $false
    }
}

function Invoke-ScriptWithRetry {
    param(
        [Parameter(Mandatory=$true)]  [string]$ScriptPath,
        [Parameter(Mandatory=$true)]  [string]$ScriptName,
        [Parameter(Mandatory=$false)] [int]$MaxRetries = 5,
        [Parameter(Mandatory=$false)] [int]$RetryDelaySeconds = 60
    )

    $Attempt = 0
    $Success = $false

    while ($Attempt -lt $MaxRetries -and -not $Success) {
        $Attempt++
        Write-Log "Attempting to run script: $ScriptName (Attempt $Attempt/$MaxRetries)" "INFO"

        if (-not (Test-Path $ScriptPath)) {
            Write-Log "Script file not found: $ScriptPath" "ERROR"
            return $false
        }

        if ($ScriptName -like "*update*" -or $ScriptName -like "*download*") {
            if (-not (Test-InternetConnection)) {
                Write-Log "No internet connection. Waiting $RetryDelaySeconds seconds..." "WARNING"
                if ($Attempt -lt $MaxRetries) {
                    Start-Sleep -Seconds $RetryDelaySeconds
                    continue
                } else {
                    Write-Log "Max retries reached. Internet still unavailable." "ERROR"
                    return $false
                }
            }
        }

        try {
            $OriginalPolicy = Get-ExecutionPolicy -Scope Process
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

            Write-Log "Executing: $ScriptPath" "INFO"
            $Output   = & $ScriptPath 2>&1
            $ExitCode = $LASTEXITCODE

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
            Write-Log "Error executing '$ScriptName': $($_.Exception.Message)" "ERROR"
            if ($Attempt -lt $MaxRetries) {
                Write-Log "Waiting $RetryDelaySeconds seconds before retry..." "WARNING"
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }
    }

    if (-not $Success) {
        Write-Log "Failed to execute '$ScriptName' after $MaxRetries attempts" "ERROR"
    }

    return $Success
}

function Initialize-Logging {
    if (-not (Test-Path $LogDir)) {
        try {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
            Write-Log "Created log directory: $LogDir" "INFO"
        } catch {
            Write-Host "Failed to create log directory: $_" -ForegroundColor Red
            $script:LogFile = Join-Path $ScriptPath "ssjmuk-task_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        }
    }

    Write-Log "========================================" "INFO"
    Write-Log "Task started: ssjmuk-task.ps1" "INFO"
    Write-Log "Computer: $env:COMPUTERNAME | User: $env:USERNAME" "INFO"
    Write-Log "Script path: $ScriptPath" "INFO"
    Write-Log "Log file: $LogFile" "INFO"
    Write-Log "========================================" "INFO"
}

function Cleanup-OldLogs {
    param([int]$DaysToKeep = 30)
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
        [Parameter(Mandatory=$true)]  [string]$GitHubUrl,
        [Parameter(Mandatory=$true)]  [string]$LocalPath,
        [Parameter(Mandatory=$true)]  [string]$ScriptName,
        [Parameter(Mandatory=$false)] [int]$MaxRetries = 5,
        [Parameter(Mandatory=$false)] [int]$RetryDelaySeconds = 10
    )

    $Attempt = 0
    $Success = $false

    while ($Attempt -lt $MaxRetries -and -not $Success) {
        $Attempt++
        Write-Log "Downloading '$ScriptName' (Attempt $Attempt/$MaxRetries)..." "INFO"

        try {
            if (-not (Test-InternetConnection)) {
                Write-Log "No internet connection. Waiting $RetryDelaySeconds seconds..." "WARNING"
                if ($Attempt -lt $MaxRetries) {
                    Start-Sleep -Seconds $RetryDelaySeconds
                    continue
                } else {
                    Write-Log "Max retries reached. Internet still unavailable." "ERROR"
                    return $false
                }
            }

            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $GitHubUrl -OutFile $LocalPath -UseBasicParsing -ErrorAction Stop

            if (Test-Path $LocalPath) {
                $FileSize = (Get-Item $LocalPath).Length
                Write-Log "Downloaded '$ScriptName' ($([math]::Round($FileSize/1KB, 2)) KB)" "SUCCESS"
                $Success = $true
            } else {
                Write-Log "Download completed but file not found: $LocalPath" "ERROR"
                if ($Attempt -lt $MaxRetries) { Start-Sleep -Seconds $RetryDelaySeconds }
            }
        } catch {
            Write-Log "Failed to download '$ScriptName': $($_.Exception.Message)" "ERROR"
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

    $AllRequiredDownloaded = $true

    foreach ($Script in $ScriptsToDownload) {
        $GitHubUrl = "$GitHubBaseUrl/$($Script.GitHubPath)"
        Write-Log "Downloading: $($Script.Name) from $GitHubUrl" "INFO"

        $Result = Download-ScriptFromGitHub `
            -GitHubUrl  $GitHubUrl `
            -LocalPath  $Script.LocalPath `
            -ScriptName $Script.Name `
            -MaxRetries $MaxRetries `
            -RetryDelaySeconds $RetryDelaySeconds

        if (-not $Result -and $Script.Required) {
            $AllRequiredDownloaded = $false
            Write-Log "Required script '$($Script.Name)' download FAILED" "ERROR"
        }
    }

    return $AllRequiredDownloaded
}

function Invoke-Step4-DownloadActiveResponse {
    Write-Log "========================================" "INFO"
    Write-Log "Step 4: Download Active Response scripts" "INFO"
    Write-Log "========================================" "INFO"

    $SystemDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' } | Select-Object -First 1).Root -replace ':\\', ''
    if (-not $SystemDrive) {
        $SystemDrive = "C"
        Write-Log "Could not detect system drive, defaulting to C:" "WARNING"
    }

    $ActiveResponsePath = "${SystemDrive}:\Program Files (x86)\ossec-agent\active-response\bin"

    if (-not (Test-Path $ActiveResponsePath)) {
        Write-Log "Active Response directory not found: $ActiveResponsePath" "WARNING"
        Write-Log "Wazuh Agent may not be installed. Skipping Step 4." "WARNING"
        return $false
    }

    Write-Log "Active Response Path: $ActiveResponsePath" "INFO"

    # Download action-script.bat
    $ActionScriptUrl  = "https://raw.githubusercontent.com/cti-misp/MISP/refs/heads/main/active-response/action-script.bat"
    $SaveActionScript = Join-Path $ActiveResponsePath "action-script.bat"

    Write-Log "Downloading action-script.bat..." "INFO"
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $ActionScriptUrl -OutFile $SaveActionScript -UseBasicParsing -ErrorAction Stop
        Write-Log "Downloaded action-script.bat ($([math]::Round((Get-Item $SaveActionScript).Length/1KB, 2)) KB)" "SUCCESS"
    } catch {
        Write-Log "Failed to download action-script.bat: $($_.Exception.Message)" "ERROR"
        return $false
    }

    # Download block-malicious.ps1
    $BlockMalUrl  = "https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main/wazuh/active-response/bin/block-malicious.ps1"
    $SaveBlockMal = Join-Path $ActiveResponsePath "block-malicious.ps1"

    Write-Log "Downloading block-malicious.ps1..." "INFO"
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $BlockMalUrl -OutFile $SaveBlockMal -UseBasicParsing -ErrorAction Stop
        Write-Log "Downloaded block-malicious.ps1 ($([math]::Round((Get-Item $SaveBlockMal).Length/1KB, 2)) KB)" "SUCCESS"
    } catch {
        Write-Log "Failed to download block-malicious.ps1: $($_.Exception.Message)" "ERROR"
        return $false
    }

    # Download Invoke-DFIRCollection.ps1 → C:\install-sysmon\
    $DFIRScriptUrl  = "https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main/Invoke-DFIRCollection.ps1"
    $DFIRScriptDir  = "C:\install-sysmon"
    $SaveDFIRScript = Join-Path $DFIRScriptDir "Invoke-DFIRCollection.ps1"

    Write-Log "Downloading Invoke-DFIRCollection.ps1 to $DFIRScriptDir..." "INFO"
    try {
        if (-not (Test-Path $DFIRScriptDir)) {
            New-Item -ItemType Directory -Path $DFIRScriptDir -Force | Out-Null
            Write-Log "Created directory: $DFIRScriptDir" "INFO"
        }
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $DFIRScriptUrl -OutFile $SaveDFIRScript -UseBasicParsing -ErrorAction Stop
        Write-Log "Downloaded Invoke-DFIRCollection.ps1 ($([math]::Round((Get-Item $SaveDFIRScript).Length/1KB, 2)) KB)" "SUCCESS"
    } catch {
        Write-Log "Failed to download Invoke-DFIRCollection.ps1: $($_.Exception.Message)" "WARNING"
        # non-critical: block-malicious.ps1 ยังทำงานได้ แค่ DFIR background จะไม่รัน
    }

    Write-Log "Step 4 completed successfully" "SUCCESS"
    return $true
}

function Invoke-Step5-RestartService {
    Write-Log "========================================" "INFO"
    Write-Log "Step 5: Restart Wazuh Service" "INFO"
    Write-Log "========================================" "INFO"

    $ServiceName = "WazuhSvc"
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if (-not $Service) {
        Write-Log "Service '$ServiceName' not found. Skipping." "WARNING"
        return $true
    }

    Write-Log "Current status: $($Service.Status)" "INFO"

    $MaxServiceRetries = 3
    $ServiceAttempt    = 0

    while ($ServiceAttempt -lt $MaxServiceRetries) {
        $ServiceAttempt++
        Write-Log "Restart attempt $ServiceAttempt/$MaxServiceRetries..." "INFO"

        try {
            # Stop ก่อนถ้ายังรันอยู่
            $CurrentService = Get-Service -Name $ServiceName -ErrorAction Stop
            if ($CurrentService.Status -ne 'Stopped') {
                Write-Log "Stopping service..." "INFO"
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop

                # รอจนหยุดจริง (max 30 วินาที)
                $WaitCount = 0
                do {
                    Start-Sleep -Seconds 2
                    $WaitCount++
                    $CurrentService = Get-Service -Name $ServiceName -ErrorAction Stop
                    Write-Log "Waiting for stop... ($($CurrentService.Status))" "INFO"
                } while ($CurrentService.Status -ne 'Stopped' -and $WaitCount -lt 15)

                if ($CurrentService.Status -ne 'Stopped') {
                    Write-Log "Service did not stop after 30s. Retrying..." "WARNING"
                    continue
                }
            }

            # Start
            Write-Log "Starting service..." "INFO"
            Start-Service -Name $ServiceName -ErrorAction Stop

            # รอจนรันจริง (max 20 วินาที)
            $WaitCount = 0
            do {
                Start-Sleep -Seconds 2
                $WaitCount++
                $CurrentService = Get-Service -Name $ServiceName -ErrorAction Stop
            } while ($CurrentService.Status -ne 'Running' -and $WaitCount -lt 10)

            if ($CurrentService.Status -eq 'Running') {
                Write-Log "Service restarted successfully. Status: $($CurrentService.Status)" "SUCCESS"
                return $true
            } else {
                Write-Log "Service did not reach Running state. Status: $($CurrentService.Status)" "WARNING"
            }

        } catch {
            Write-Log "Attempt $ServiceAttempt failed: $($_.Exception.Message)" "WARNING"
        }

        if ($ServiceAttempt -lt $MaxServiceRetries) {
            Write-Log "Waiting 10s before next attempt..." "INFO"
            Start-Sleep -Seconds 10
        }
    }

    Write-Log "Failed to restart '$ServiceName' after $MaxServiceRetries attempts" "ERROR"
    return $false
}

function Invoke-Step6-BlockFoxitFirewall {
    Write-Log "========================================" "INFO"
    Write-Log "Step 6: Block All Foxit Software Outbound (Firewall)" "INFO"
    Write-Log "========================================" "INFO"

    # Resolve base paths - ครอบคลุมทุก product ใน Foxit Software folder
    $PF86    = ${env:ProgramFiles(x86)}
    $PF64    = ${env:ProgramFiles}
    $AppData = $env:APPDATA

    if (-not $PF86) {
        $PF86 = $env:ProgramFiles
        Write-Log "ProgramFiles(x86) not found, falling back to ProgramFiles: $PF86" "WARNING"
    }

    # Scan root "Foxit Software" ทั้งสอง location - recursive ครอบทุก product
    $ScanPaths = @(
        @{ Label = "ProgramFiles(x86)"; Path = Join-Path $PF86    "Foxit Software" },
        @{ Label = "ProgramFiles"; Path = Join-Path $PF64    "Foxit Software" },
        @{ Label = "AppData";      Path = Join-Path $AppData "Foxit Software" }
    )

    $AnyFailed   = $false
    $TotalBlocked = 0

    foreach ($Scan in $ScanPaths) {
        Write-Log "Scanning: [$($Scan.Label)] $($Scan.Path)" "INFO"

        if (-not (Test-Path $Scan.Path)) {
            Write-Log "  Path not found - Foxit may not be installed here, skipping: $($Scan.Path)" "WARNING"
            continue
        }

        # Enumerate .exe ทุกตัวแบบ recursive (ครอบ PhantomPDF, PDF Reader, PDF Editor ฯลฯ)
        $Exes = Get-ChildItem -Path $Scan.Path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
        if (-not $Exes) {
            Write-Log "  No .exe files found under: $($Scan.Path)" "WARNING"
            continue
        }

        Write-Log "  Found $($Exes.Count) exe(s) - creating firewall rules..." "INFO"

        foreach ($Exe in $Exes) {
            # ชื่อ rule: "Block Foxit [label] [relative path]" เพื่อหลีกเลี่ยงชื่อซ้ำข้าม product
            $RelPath     = $Exe.FullName.Substring($Scan.Path.Length).TrimStart('\')
            $RuleName    = "Block Foxit [$($Scan.Label)] $RelPath Outbound"

            try {
                # ใช้ Where-Object นับจำนวนจริง -- Get-NetFirewallRule ไม่ throw เมื่อไม่เจอ rule
                # จึงตรวจด้วย Count แทนการ cast เป็น bool
                $ExistingRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -eq $RuleName })

                if ($ExistingRules.Count -gt 0) {
                    Write-Log "  Rule already exists ($($ExistingRules.Count) copy) - skipping: $RelPath" "INFO"
                    continue
                }

                New-NetFirewallRule `
                    -DisplayName  $RuleName `
                    -Direction    Outbound `
                    -Action       Block `
                    -Program      $Exe.FullName `
                    -Profile      Any `
                    -Enabled      True `
                    -Description  "Blocked by SSJMUK automation script" `
                    -ErrorAction  Stop | Out-Null

                Write-Log "  Blocked: $RelPath" "SUCCESS"
                $TotalBlocked++

            } catch {
                Write-Log "  Failed to create rule for '$RelPath': $($_.Exception.Message)" "ERROR"
                $AnyFailed = $true
            }
        }

        Write-Log "  Done scanning [$($Scan.Label)]: $($Exes.Count) exe(s) processed" "INFO"
    }

    Write-Log "Total rules created: $TotalBlocked" "INFO"

    if ($AnyFailed) {
        Write-Log "Step 6 completed with some errors" "WARNING"
        return $false
    }

    Write-Log "Step 6 completed successfully" "SUCCESS"
    return $true
}

function Invoke-Step7-UpgradeWazuhAgent {
    param(
        [Parameter(Mandatory=$true)] [string]$TargetVersion,
        [Parameter(Mandatory=$true)] [string]$DownloadUrl
    )

    Write-Log "========================================" "INFO"
    Write-Log "Step 7: Upgrade Wazuh Agent" "INFO"
    Write-Log "Target Version : $TargetVersion" "INFO"
    Write-Log "Download URL   : $DownloadUrl" "INFO"
    Write-Log "========================================" "INFO"

    # ── 1. ตรวจ version ปัจจุบันจาก wazuh-agent.exe PE header ──────────────────
    $AgentDir  = "${env:ProgramFiles(x86)}\ossec-agent"
    $AgentExe  = Join-Path $AgentDir "wazuh-agent.exe"

    if (-not (Test-Path $AgentExe)) {
        Write-Log "Wazuh Agent not found at '$AgentExe'. Skipping upgrade." "WARNING"
        return $false
    }

    try {
        $CurrentVersion = (Get-Item $AgentExe -ErrorAction Stop).VersionInfo.ProductVersion -replace '^v',''
        if (-not $CurrentVersion) {
            Write-Log "ProductVersion is empty in wazuh-agent.exe. Cannot determine current version." "ERROR"
            return $false
        }
        Write-Log "Current version : $CurrentVersion (from wazuh-agent.exe ProductVersion)" "INFO"
        Write-Log "Target  version : $TargetVersion" "INFO"
    } catch {
        Write-Log "Failed to read version from wazuh-agent.exe: $($_.Exception.Message)" "ERROR"
        return $false
    }

    # เปรียบเทียบด้วย [System.Version] เพื่อรองรับ semantic versioning
    try {
        $CurrentVer = [System.Version]$CurrentVersion
        $TargetVer  = [System.Version]$TargetVersion
    } catch {
        Write-Log "Version parse error - current='$CurrentVersion' target='$TargetVersion': $($_.Exception.Message)" "ERROR"
        return $false
    }

    if ($CurrentVer -ge $TargetVer) {
        Write-Log "Already at version $CurrentVersion (>= $TargetVersion). No upgrade needed." "SUCCESS"
        $script:WazuhVersionInfo = "v$CurrentVersion (up-to-date)"
        return $true
    }

    Write-Log "Upgrade required: $CurrentVersion -> $TargetVersion" "INFO"

    # ── 2. ตรวจ internet ก่อน download ────────────────────────────────────────
    if (-not (Test-InternetConnection)) {
        Write-Log "No internet connection. Cannot download installer." "ERROR"
        return $false
    }

    # ── 3. Download MSI ────────────────────────────────────────────────────────
    $MsiFileName = Split-Path $DownloadUrl -Leaf
    $TempDir     = Join-Path $env:TEMP "WazuhUpgrade"
    $MsiPath     = Join-Path $TempDir $MsiFileName

    try {
        if (-not (Test-Path $TempDir)) {
            New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
        }
        Write-Log "Downloading installer to: $MsiPath" "INFO"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $MsiPath -UseBasicParsing -ErrorAction Stop
        $MsiBytes = (Get-Item $MsiPath).Length
        $MsiSize  = [math]::Round($MsiBytes / 1048576, 2)
        Write-Log "Download complete: $MsiSize MB" "SUCCESS"
    } catch {
        Write-Log "Download failed: $($_.Exception.Message)" "ERROR"
        return $false
    }

    # ── 4. Run installer (Wazuh docs: .\wazuh-agent-x.x.x-1.msi /q) ──────────
    # /q  = quiet (no UI)
    # /norestart = ไม่ reboot อัตโนมัติ
    Write-Log "Running installer: $MsiPath /q" "INFO"
    try {
        $InstallArgs = "/i `"$MsiPath`" /q /norestart"
        $Process = Start-Process -FilePath "msiexec.exe" `
                                 -ArgumentList $InstallArgs `
                                 -Wait -PassThru -ErrorAction Stop
        Write-Log "Installer exited with code: $($Process.ExitCode)" "INFO"

        # msiexec exit codes: 0 = success, 3010 = success + reboot required
        if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
            if ($Process.ExitCode -eq 3010) {
                Write-Log "Installer requests reboot - please restart the machine when convenient." "WARNING"
            }
        } else {
            Write-Log "Installer returned non-zero exit code: $($Process.ExitCode)" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Failed to run installer: $($_.Exception.Message)" "ERROR"
        return $false
    }

    # ── 5. Verify version หลัง upgrade ────────────────────────────────────────
    Start-Sleep -Seconds 5   # รอ installer replace wazuh-agent.exe เสร็จ
    try {
        $NewVersion = (Get-Item $AgentExe -ErrorAction Stop).VersionInfo.ProductVersion -replace '^v',''
        Write-Log "Installed version: $NewVersion (from wazuh-agent.exe ProductVersion)" "INFO"

        if ([System.Version]$NewVersion -ge $TargetVer) {
            Write-Log "Upgrade verified successfully: $CurrentVersion -> $NewVersion" "SUCCESS"
            $script:WazuhVersionInfo = "v$CurrentVersion → v$NewVersion"
        } else {
            Write-Log "Version after install ($NewVersion) is still lower than target ($TargetVersion)" "WARNING"
            $script:WazuhVersionInfo = "v$CurrentVersion → v$NewVersion (verify failed)"
        }
    } catch {
        Write-Log "Could not verify version after install: $($_.Exception.Message)" "WARNING"
    }

    # ── 6. Restart Wazuh service ───────────────────────────────────────────────
    Write-Log "Restarting WazuhSvc after upgrade..." "INFO"
    $RestartOk = Invoke-Step5-RestartService
    if (-not $RestartOk) {
        Write-Log "Service restart failed after upgrade - manual check required." "WARNING"
    }

    # ── 7. Cleanup temp file ───────────────────────────────────────────────────
    try {
        Remove-Item $MsiPath -Force -ErrorAction SilentlyContinue
        Write-Log "Cleaned up temp installer: $MsiPath" "INFO"
    } catch {
        Write-Log "Could not remove temp file '$MsiPath': $($_.Exception.Message)" "WARNING"
    }

    Write-Log "Step 7 completed successfully" "SUCCESS"
    return $true
}

function Invoke-Step8-RotateLogs {
    Write-Log "========================================" "INFO"
    Write-Log "Step 8: Log Rotation (90-day retention)" "INFO"
    Write-Log "========================================" "INFO"

    $RetentionDays = 90
    $CutoffDate    = (Get-Date).AddDays(-$RetentionDays)
    $AnyFailed     = $false

    # ── 8a. Sysmon install logs: C:\install-sysmon\logs ──────────────────────────
    $SysmonLogDir = $LogDir
    Write-Log "8a: Rotating Sysmon logs at: $SysmonLogDir" "INFO"

    if (Test-Path $SysmonLogDir) {
        try {
            $OldFiles = Get-ChildItem -Path $SysmonLogDir -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $CutoffDate }

            if ($OldFiles -and $OldFiles.Count -gt 0) {
                $DeleteCount = 0
                foreach ($File in $OldFiles) {
                    try {
                        Remove-Item -Path $File.FullName -Force -ErrorAction Stop
                        $DeleteCount++
                    } catch {
                        Write-Log "  Failed to delete '$($File.FullName)': $($_.Exception.Message)" "WARNING"
                        $AnyFailed = $true
                    }
                }
                Write-Log "8a: Deleted $DeleteCount file(s) older than $RetentionDays days from $SysmonLogDir" "SUCCESS"
            } else {
                Write-Log "8a: No files older than $RetentionDays days found in $SysmonLogDir" "INFO"
            }
        } catch {
            Write-Log "8a: Error scanning $SysmonLogDir - $($_.Exception.Message)" "WARNING"
            $AnyFailed = $true
        }
    } else {
        Write-Log "8a: Sysmon log directory not found, skipping: $SysmonLogDir" "WARNING"
    }

    # ── 8b. Wazuh active-responses.log rotation ───────────────────────────────────
    # Strategy:
    #   1. If active-responses.log exists and is NOT from today, rename it to active-responses.log.YYYYMMDD
    #   2. Delete archived files older than 90 days
    #   3. The current active-responses.log (today's) is untouched by Wazuh
    $ArDir      = "${env:ProgramFiles(x86)}\ossec-agent\active-response"
    $LiveLog    = Join-Path $ArDir "active-responses.log"
    $TodayStamp = Get-Date -Format "yyyyMMdd"

    Write-Log "8b: Rotating active-responses.log at: $ArDir" "INFO"

    if (Test-Path $ArDir) {

        # Rotate the live log if it exists and was last written before today
        if (Test-Path $LiveLog) {
            $LiveLogDate = (Get-Item $LiveLog).LastWriteTime.Date
            $TodayDate   = (Get-Date).Date

            if ($LiveLogDate -lt $TodayDate) {
                $ArchiveName = "active-responses.log.$((Get-Item $LiveLog).LastWriteTime.ToString('yyyyMMdd'))"
                $ArchivePath = Join-Path $ArDir $ArchiveName

                # Avoid overwriting an existing archive for that date
                if (-not (Test-Path $ArchivePath)) {
                    try {
                        Rename-Item -Path $LiveLog -NewName $ArchiveName -ErrorAction Stop
                        Write-Log "8b: Rotated active-responses.log -> $ArchiveName" "SUCCESS"
                        # สร้างไฟล์หลักว่างเปล่าไว้รองรับ Wazuh active response ที่จะเกิดขึ้น
                        New-Item -ItemType File -Path $LiveLog -Force -ErrorAction Stop | Out-Null
                        Write-Log "8b: Created new empty active-responses.log" "INFO"
                    } catch {
                        Write-Log "8b: Failed to rotate active-responses.log: $($_.Exception.Message)" "WARNING"
                        $AnyFailed = $true
                    }
                } else {
                    # Archive for that date already exists - append content then clear live log
                    try {
                        $LiveContent = Get-Content -Path $LiveLog -Raw -ErrorAction Stop
                        Add-Content -Path $ArchivePath -Value $LiveContent -ErrorAction Stop
                        Clear-Content -Path $LiveLog -ErrorAction Stop
                        Write-Log "8b: Appended to existing archive $ArchiveName and cleared live log" "SUCCESS"
                    } catch {
                        Write-Log "8b: Failed to merge into existing archive: $($_.Exception.Message)" "WARNING"
                        $AnyFailed = $true
                    }
                }
            } else {
                Write-Log "8b: active-responses.log is from today - no rotation needed" "INFO"
            }
        } else {
            Write-Log "8b: active-responses.log not found at $LiveLog" "INFO"
        }

        # Delete archived files older than 90 days (pattern: active-responses.log.YYYYMMDD)
        try {
            $OldArchives = Get-ChildItem -Path $ArDir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^active-responses\.log\.\d{8}$' -and $_.LastWriteTime -lt $CutoffDate }

            if ($OldArchives -and $OldArchives.Count -gt 0) {
                $DeleteCount = 0
                foreach ($Archive in $OldArchives) {
                    try {
                        Remove-Item -Path $Archive.FullName -Force -ErrorAction Stop
                        $DeleteCount++
                    } catch {
                        Write-Log "  Failed to delete archive '$($Archive.Name)': $($_.Exception.Message)" "WARNING"
                        $AnyFailed = $true
                    }
                }
                Write-Log "8b: Deleted $DeleteCount archive file(s) older than $RetentionDays days" "SUCCESS"
            } else {
                Write-Log "8b: No archives older than $RetentionDays days found" "INFO"
            }
        } catch {
            Write-Log "8b: Error scanning archives in $ArDir - $($_.Exception.Message)" "WARNING"
            $AnyFailed = $true
        }

    } else {
        Write-Log "8b: ossec-agent active-response directory not found, skipping: $ArDir" "WARNING"
    }

    if ($AnyFailed) {
        Write-Log "Step 8 completed with some warnings" "WARNING"
        return $false
    }

    Write-Log "Step 8 completed successfully" "SUCCESS"
    return $true
}
#endregion

#region Main Execution
# ตัวแปร track สาเหตุ abort สำหรับส่งใน summary
$script:AbortReason = $null

try {
    Initialize-Logging
    Cleanup-OldLogs

    Write-Log "Computer: $env:COMPUTERNAME | User: $env:USERNAME" "INFO"
    Write-Log "PowerShell: $($PSVersionTable.PSVersion)" "INFO"
    Write-Log "GitHub Base: $GitHubBaseUrl" "INFO"

    # Download scripts
    $AllScriptsDownloaded = Download-AllScripts

    $OverallSuccess = $true
    $ScriptResults  = [System.Collections.Generic.List[hashtable]]::new()

    if (-not $AllScriptsDownloaded) {
        Write-Log "Required scripts failed to download. Aborting." "ERROR"
        $script:AbortReason = "Failed to download required scripts from GitHub"
        $OverallSuccess = $false

        # เพิ่ม abort เป็น result entry เพื่อแสดงใน summary
        $ScriptResults.Add(@{ Name = "Download-Scripts"; Success = $false; Required = $true })

    } else {

        # Run scripts
        foreach ($Script in $ScriptsToRun) {
            Write-Log "Processing: $($Script.Name)" "INFO"

            $Result = Invoke-ScriptWithRetry `
                -ScriptPath        $Script.Path `
                -ScriptName        $Script.Name `
                -MaxRetries        $MaxRetries `
                -RetryDelaySeconds $RetryDelaySeconds

            $ScriptResults.Add(@{
                Name     = $Script.Name
                Success  = $Result
                Required = $Script.Required
            })

            if (-not $Result -and $Script.Required) {
                $OverallSuccess = $false
                Write-Log "Required script '$($Script.Name)' FAILED" "ERROR"
            }
        }

        # Step 4
        $Step4Result = Invoke-Step4-DownloadActiveResponse
        $ScriptResults.Add(@{ Name = "Step4-DownloadActiveResponse"; Success = $Step4Result; Required = $false })
        if (-not $Step4Result) { Write-Log "Step 4 failed (non-critical)" "WARNING" }

        # Step 5
        $Step5Result = Invoke-Step5-RestartService
        $ScriptResults.Add(@{ Name = "Step5-RestartWazuhService"; Success = $Step5Result; Required = $false })
        if (-not $Step5Result) { Write-Log "Step 5 failed (non-critical)" "WARNING" }

        # Step 6
        $Step6Result = Invoke-Step6-BlockFoxitFirewall
        $ScriptResults.Add(@{ Name = "Step6-BlockFoxitFirewall"; Success = $Step6Result; Required = $false })
        if (-not $Step6Result) { Write-Log "Step 6 failed (non-critical)" "WARNING" }

        # Step 7
        $Step7Result = Invoke-Step7-UpgradeWazuhAgent -TargetVersion $VersionWazuh -DownloadUrl $URL_Download
        $ScriptResults.Add(@{ Name = "Step7-UpgradeWazuhAgent"; Success = $Step7Result; Required = $false })
        if (-not $Step7Result) { Write-Log "Step 7 failed (non-critical)" "WARNING" }

        # Step 8
        $Step8Result = Invoke-Step8-RotateLogs
        $ScriptResults.Add(@{ Name = "Step8-RotateLogs"; Success = $Step8Result; Required = $false })
        if (-not $Step8Result) { Write-Log "Step 8 failed (non-critical)" "WARNING" }
    }

    # Summary log
    Write-Log "========================================" "INFO"
    Write-Log "Task Summary:" "INFO"
    foreach ($Result in $ScriptResults) {
        $LogLevel = if ($Result.Success) { "SUCCESS" } else { "ERROR" }
        $Status   = if ($Result.Success) { "SUCCESS" } else { "FAILED" }
        $Required = if ($Result.Required) { "(Required)" } else { "(Optional)" }
        Write-Log "  $($Result.Name): $Status $Required" $LogLevel
    }

    # ส่ง Discord summary ครั้งเดียว
    Send-DiscordSummary -OverallSuccess $OverallSuccess -Results $ScriptResults

    if ($OverallSuccess) {
        Write-Log "All required tasks completed successfully!" "SUCCESS"
        exit 0
    } else {
        Write-Log "One or more required tasks failed!" "ERROR"
        exit 1
    }

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"

    # fatal error ก็ยังส่งผ่าน summary เดิม ไม่ส่งแยก
    $ScriptResults = [System.Collections.Generic.List[hashtable]]::new()
    $ScriptResults.Add(@{ Name = "Fatal-Error: $($_.Exception.Message)"; Success = $false; Required = $true })
    Send-DiscordSummary -OverallSuccess $false -Results $ScriptResults

    exit 1
} finally {
    Write-Log "Task completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Log "Log: $LogFile" "INFO"
}
#endregion
