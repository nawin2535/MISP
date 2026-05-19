# ============================================
# Block Microsoft Office EXE
# Inbound + Outbound Firewall Rules
# Run PowerShell as Administrator
# ============================================

$officePath = "C:\Program Files\Microsoft Office\root\Office16"

# รายชื่อโปรแกรม Office ที่ต้องการ block
$officeApps = @(
    "WINWORD.EXE",
    "EXCEL.EXE",
    "POWERPNT.EXE",
    "OUTLOOK.EXE",
    "MSACCESS.EXE",
    "ONENOTE.EXE",
    "VISIO.EXE",
    "LYNC.EXE",
    "Teams.exe"
)

foreach ($app in $officeApps) {

    $fullPath = Join-Path $officePath $app

    if (Test-Path $fullPath) {

        Write-Host "Creating firewall rules for $app" -ForegroundColor Green

        # OUTBOUND BLOCK
        New-NetFirewallRule `
            -DisplayName "BLOCK_OUT_$app" `
            -Direction Outbound `
            -Program $fullPath `
            -Action Block `
            -Profile Any `
            -Enabled True

        # INBOUND BLOCK
        New-NetFirewallRule `
            -DisplayName "BLOCK_IN_$app" `
            -Direction Inbound `
            -Program $fullPath `
            -Action Block `
            -Profile Any `
            -Enabled True
    }
    else {
        Write-Host "$app not found" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Microsoft Office firewall block done." -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan