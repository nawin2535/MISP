# update-sysmon-config.ps1
# open powershell admin & Run this command first : 
## Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
$url = "https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main/sysmonconfig-export-v2.xml"
$localXml = "C:\temp\sysmonconfig-export-v2.xml"

Write-Host "Downloading latest config..."
Invoke-WebRequest -Uri $url -OutFile $localXml

Write-Host "Applying config..."
& "Sysmon.exe" -c $localXml

Write-Host "Done. Current config:"
& "Sysmon.exe" -c | findstr "pdf"