## Before you proceed to step 1, you must have the wazuh agent installed.
## ก่อนคุณจะเริ่มดำเนินการ run file นี้ คุณต้องติดตั้ง wazuh agent ให้เรียบร้อยก่อน
## ----------------------------------------------------------
## step 1 : ##
Write-Output "#### Install Sysmon & Config Wazuh Agent : ####"
Write-Output "#### Step1 : download sysmon & sysmon_config ####"
# Enable execution Policy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
## Get-ExecutionPolicy

# Define function to find the system drive
$SystemDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' } | Select-Object -First 1).Root -replace ':\\', ''

# Define installation directory
$InstallDir = "${SystemDrive}:\install-sysmon"

# Check if the directory exists, if not, create it
if (!(Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Define Sysmon download URL
$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$ZipPath = "${InstallDir}\Sysmon.zip"

# Download Sysmon
try {
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $ZipPath
    Write-Output "Downloaded Sysmon to ${ZipPath}"
} catch {
    Write-Output "Error: Failed to download Sysmon"
    exit 1
}

# Extract Zip file
try {
    Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
    Write-Output "Extracted Sysmon to ${InstallDir}"
} catch {
    Write-Output "Error: Failed to extract Sysmon"
    exit 1
}

## Test : ##
## $InstallDir = "C:\install-sysmon"

# Define Sysmon configuration file download URL
$SysmonConfigUrl = "https://raw.githubusercontent.com/cti-misp/MISP/refs/heads/main/sysmon/sysmonconfig-export.xml"
$ConfigPath = "${InstallDir}\sysmonconfig-export.xml"

# Download Sysmon configuration file
try {
    Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $ConfigPath
    Write-Output "Downloaded Sysmon configuration to ${ConfigPath}"
} catch {
    Write-Output "Error: Failed to download Sysmon configuration"
    exit 1
}


## step 2 : ##
Write-Output "#### Step2 : Install Sysmon ####"
# Test  : Define installation directory
## $InstallDir = "C:\install-sysmon"

# Define installation directory
## $InstallDir = "${SystemDrive}\install-sysmon"
$SysmonExe = "${InstallDir}\Sysmon.exe"
$SysmonExe64 = "${InstallDir}\Sysmon64.exe"
$SysmonConfig = "${InstallDir}\sysmonconfig-export.xml"

# Install Sysmon with configuration
if ((Test-Path $SysmonExe) -and (Test-Path $SysmonConfig)) {
    & $SysmonExe -accepteula -i $SysmonConfig
    & $SysmonExe64 -accepteula -i $SysmonConfig
    Write-Output "Sysmon installed successfully with configuration."
} else {
    Write-Output "Error: Sysmon executable or configuration file not found."
    exit 1
}


## Before you proceed to step 3, you must have the wazuh agent installed.
## step 3 : ##
Write-Output "#### Step3 : Config wazuh agent for Sysmon & Active Response ####"

# Define ossec.conf path
$OssecConfPath = "${SystemDrive}:\Program Files (x86)\ossec-agent\ossec.conf"

## Test ##
## $OssecConfPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Define new localfile entry
$SysmonLine = @"
    <localfile>
        <location>Microsoft-Windows-Sysmon/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>
"@

$ActiveResponseLine = @"
    <active-response>
        <disabled>no</disabled>
        <repeated_offenders>60,300,600</repeated_offenders>
    </active-response>
"@

# Check if ossec.conf exists
if (Test-Path $OssecConfPath) {
    $OssecConfContent = Get-Content $OssecConfPath -Raw
    
    if ($OssecConfContent -notmatch [regex]::Escape($SysmonLine.Trim())) {
        
        # อ่านไฟล์และเพิ่มโค้ดที่ต้องการหลังจาก `</localfile>` สุดท้าย
        $UpdatedContent = $OssecConfContent -replace '(</localfile>)(?![\s\S]*</localfile>)', "`$1`n$SysmonLine"
        
        # Save the updated content
        $UpdatedContent | Set-Content -Path $OssecConfPath -Encoding UTF8
        Write-Output "Updated ossec.conf with Sysmon event monitoring."
    } else {
        Write-Output "ossec.conf already contains Sysmon event monitoring entry."
    }

    if ($OssecConfContent -notmatch [regex]::Escape($ActiveResponseLine.Trim())) {
        
        # อ่านไฟล์และเพิ่มโค้ดที่ต้องการหลังจาก `</localfile>` สุดท้าย
        $UpdatedContent = $OssecConfContent -replace '(</active-response>)(?![\s\S]*</active-response>)', "`$1`n$ActiveResponseLine"
        
        # Save the updated content
        $UpdatedContent | Set-Content -Path $OssecConfPath -Encoding UTF8
        Write-Output "Updated ossec.conf with Active response."
    } else {
        Write-Output "ossec.conf already contains Active response entry."
    }
} else {
    Write-Output "Error: ossec.conf file not found."
    exit 1
}


## step 4 : ##
Write-Output "#### Step4 : download action-script & block-malicious.ps1 ####"

## Define ActiveResonse Wazuh Directory : ##
$ActiveResponsePath = "${SystemDrive}:\Program Files (x86)\ossec-agent\active-response\bin"

## Test : ##
## $ActiveResponsePath = "C:\Program Files (x86)\ossec-agent\active-response\bin"

# Define action-script file download URL
$ActionScriptUrl = "https://raw.githubusercontent.com/cti-misp/MISP/refs/heads/main/active-response/action-script.bat"
$SaveActionScriptPath = "${ActiveResponsePath}\action-script.bat"

# Download Sysmon configuration file
try {
    Invoke-WebRequest -Uri $ActionScriptUrl -OutFile $SaveActionScriptPath
    Write-Output "Downloaded action-script to ${SaveActionScriptPath}"
} catch {
    Write-Output "Error: Failed to download action-script"
    exit 1
}


# Define block-malicious file download URL
# $BlockMalUrl = "https://raw.githubusercontent.com/cti-misp/MISP/refs/heads/main/active-response/block-malicious.ps1"
$BlockMalUrl = "https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main/wazuh/active-response/bin/block-malicious.ps1"
$SaveBlockMalPath = "${ActiveResponsePath}\block-malicious.ps1"

# Download Sysmon configuration file
try {
    Invoke-WebRequest -Uri $BlockMalUrl -OutFile $SaveBlockMalPath
    Write-Output "Downloaded block-malicious to ${SaveBlockMalPath}"
} catch {
    Write-Output "Error: Failed to download block-malicious"
    exit 1
}


## step 5 : ##
Write-Output "#### Step5 : Restart Service ####"

try {
    ## Restart Wazuh Agent service ##
    Restart-Service -Name "WazuhSvc" -Force
    Write-Output "Success: WazuhSvc restarted successfully."
} catch {
    Write-Output "Error: Failed to restart WazuhSvc - $_"
}

try {
    ## Disable Execution Policy ##
    Set-ExecutionPolicy Restricted -Scope CurrentUser -Force
    Write-Output "Success: Execution Policy set to Restricted."
} catch {
    Write-Output "Error: Failed to change Execution Policy - $_"
}