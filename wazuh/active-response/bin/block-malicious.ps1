################################
## PowerShell Active Response for MISP IoC
## Full features: File delete (Event 15), IP block (Event 3), Domain block (Event 22)
## Super detailed logging for debugging
## Safe stdin reading + error handling
################################

# Log file
$logFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

# Helper function to log with timestamp (safe, no suppression)
function Log-Detail {
    param([string]$msg)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    try {
        "$timestamp - $msg" | Out-File -FilePath $logFile -Append -Encoding utf8 -ErrorAction Stop
    } catch {
        # Fallback ถ้า log เขียนไม่ได้
        Write-Output "$timestamp - LOG WRITE ERROR: $msg"
    }
}

Log-Detail "=== AR SCRIPT STARTED (PowerShell) ==="

# 1. Read stdin safely (multiple fallback methods)
Log-Detail "Step 1: Attempting to read stdin..."

$inputJson = ""
try {
    # Method 1: ReadToEnd (preferred)
    $inputJson = Read-Host
    #$inputJson = [Console]::In.ReadToEnd()
    Log-Detail "ReadToEnd success. Length: $($inputJson.Length) chars"
} catch {
    Log-Detail "ReadToEnd failed: $($_.Exception.Message)"
}

# Fallback if empty
if ([string]::IsNullOrWhiteSpace($inputJson)) {
    Log-Detail "ReadToEnd got empty - trying fallback loop..."
    try {
        $lines = @()
        while ($line = [Console]::In.ReadLine()) {
            $lines += $line
        }
        $inputJson = $lines -join "`n"
        Log-Detail "Fallback loop success. Length: $($inputJson.Length) chars"
    } catch {
        Log-Detail "Fallback loop failed: $($_.Exception.Message)"
    }
}

# Critical check
if ([string]::IsNullOrWhiteSpace($inputJson)) {
    Log-Detail "CRITICAL: STDIN is completely empty after all attempts"
    Log-Detail "This means Wazuh did not send data or pipe is broken"
    exit 1
}

# Log raw input preview (limit to 2000 chars to avoid huge log)
$preview = if ($inputJson.Length -gt 2000) { $inputJson.Substring(0,2000) + "..." } else { $inputJson }
Log-Detail "RAW INPUT_JSON (preview):"
Log-Detail $preview

# 2. Parse JSON
Log-Detail "Step 2: Trying to parse JSON..."
try {
    $alertData = $inputJson | ConvertFrom-Json -ErrorAction Stop
    Log-Detail "JSON parsed successfully"
} catch {
    Log-Detail "FATAL: JSON parse error - $($_.Exception.Message)"
    Log-Detail "Raw input (truncated): $($inputJson.Substring(0, [Math]::Min(2000, $inputJson.Length)))..."
    exit 1
}

# 3. Extract basic fields
$command = $alertData.command
Log-Detail "Command received: $command"

$parameters = $alertData.parameters
$alert = $parameters.alert
if (-not $alert) {
    Log-Detail "ERROR: No 'parameters.alert' in JSON"
    exit 1
}

$rule = $alert.rule
$rule_id = $rule.id
$groups = $rule.groups
Log-Detail "Rule ID: $rule_id"
Log-Detail "Groups: $($groups -join ', ')"

# 4. Check if MISP alert
$isMisp = ($rule_id -eq "100622") -and ($groups -contains "misp" -or $groups -contains "misp_alert")
Log-Detail "Is MISP alert? $isMisp"

# Get host IP (for skip self-block in IP case)
$hostip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*" }).IPAddress | Select-Object -First 1
Log-Detail "Local IP (for skip): $hostip"

if ($isMisp) {
    Log-Detail "Entering MISP handling block"

    $data = $alert.data
    $misp = $data.misp
    if (-not $misp) {
        Log-Detail "ERROR: No 'data.misp' found in alert"
        exit 1
    }

    $iocValue     = $misp.value
    $iocCategory  = $misp.category
    $sourceDesc   = $misp.source.description

    Log-Detail "MISP IoC value: $iocValue"
    Log-Detail "MISP Category: $iocCategory"
    Log-Detail "Source Description: $sourceDesc"

    # Case: File hash from Event 15 (Payload delivery)
    if ($sourceDesc -match "Event 15" -and $iocValue -match "^[A-Fa-f0-9]{64}$") {
        Log-Detail "Detected Event 15 + valid SHA256 pattern"

        # Parse file path
        if ($sourceDesc -match "Event 15:\s*(.+?)\s*FileCreateStreamHash") {
            $filePath = $matches[1].Trim()
            $filePath = $filePath -replace '\\\\', '\'
            Log-Detail "Parsed file path: $filePath"

            if (Test-Path $filePath) {
                Log-Detail "File exists at: $filePath"

                try {
                    $fileHash = (Get-FileHash $filePath -Algorithm SHA256 -ErrorAction Stop).Hash
                    Log-Detail "Actual file hash: $fileHash"

                    if ($fileHash -eq $iocValue) {
                        Log-Detail "Hash MATCH! Attempting to delete file..."
                        Remove-Item $filePath -Force -ErrorAction Stop
                        Log-Detail "SUCCESS: Deleted malicious file $filePath (SHA256: $iocValue)"
                    } else {
                        Log-Detail "Hash MISMATCH (expected $iocValue, got $fileHash) - not deleting"
                    }
                } catch {
                    Log-Detail "ERROR during hash check or delete: $($_.Exception.Message)"
                    Log-Detail "Stack trace: $($_.ScriptStackTrace)"
                }
            } else {
                Log-Detail "File NOT FOUND: $filePath"
            }
        } else {
            Log-Detail "Failed to parse file path from description"
        }
    } else {
        Log-Detail "Not Event 15 or invalid hash format - skipping file delete"
    }
} else {
    Log-Detail "Not a MISP alert (rule $rule_id or groups not match)"
}

# =======================================
# Original logic: IP block (Event 3)
# =======================================
$winSystem = $alert.data.win.system
$winEventdata = $alert.data.win.eventdata

if ($winSystem.eventID -eq '3') {
    Log-Detail "Detected Event 3 (Network connection) - entering IP block logic"

    $IOCvalue = $winEventdata.destinationIp
    Log-Detail "Destination IP(s): $IOCvalue"

    foreach ($ip in $IOCvalue) {
        $existingRule = Get-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" -ErrorAction SilentlyContinue
        if ($command -eq 'add' -and $ip -ne '127.0.0.1' -and $ip -ne '0.0.0.0' -and $ip -ne $hostip -and -not $existingRule) {
            Log-Detail "Adding firewall rule for IP: $ip"
            New-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" -Direction Outbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress $ip
            Log-Detail "$ip added to blocklist via Windows Firewall"
        } elseif ($command -eq 'delete' -and $ip -ne '127.0.0.1' -and $ip -ne '0.0.0.0' -and $ip -ne $hostip -and $existingRule) {
            Log-Detail "Removing firewall rule for IP: $ip"
            Remove-NetFirewallRule -DisplayName "Wazuh Active Response - $ip"
            Log-Detail "$ip removed from blocklist via Windows Firewall"
        }
    }
}

# =======================================
# Original logic: Domain block (Event 22)
# =======================================
if ($winSystem.eventID -eq '22') {
    Log-Detail "Detected Event 22 (DNS Query) - entering domain block logic"

    $IOCvaluequeryname = $winEventdata.queryName
    Log-Detail "Query Name (domain): $IOCvaluequeryname"

    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $hostEntry = "127.0.0.1`t$IOCvaluequeryname"

    if (-not (Select-String -Path $hostsPath -Pattern "^127\.0\.0\.1`t$IOCvaluequeryname$" -Quiet)) {
        Add-Content -Path $hostsPath -Value $hostEntry
        Log-Detail "$IOCvaluequeryname added to hosts file with 127.0.0.1"
    } else {
        Log-Detail "Domain $IOCvaluequeryname already blocked in hosts file"
    }
}

Log-Detail "=== AR SCRIPT ENDED ==="
exit 0