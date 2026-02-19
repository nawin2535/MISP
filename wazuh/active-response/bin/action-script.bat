:: action-script.cmd — tiny wrapper; lets PowerShell read AR JSON from STDIN
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\block-malicious.ps1"
endlocal
exit /b 0
