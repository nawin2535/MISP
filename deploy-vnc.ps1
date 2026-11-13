<#
deploy-vnc.ps1 - ติดตั้ง/ดูแล TightVNC Server สำหรับ helpdesk (เรียกจาก ssjmuk-task.ps1 Step 9 ; รันเป็น SYSTEM)

repo นี้เป็น public: ไฟล์นี้ไม่มีรหัส / IP / port / รายชื่อเครื่อง
ค่าทั้งหมดอ่านจาก ssjmuk-vnc.SECRET ที่ Wazuh manager ส่งมาใน shared ของ agent group (อ่านได้เฉพาะ admin/SYSTEM)
  Password=<hex> ControlPassword=<hex> Port=<10000-49151> Helpdesk=<ip,ip> Targets=<COMPUTERNAME,...|all>

ห้ามมีขั้นโต้ตอบ (SYSTEM / session 0) ; ไม่แสดงค่ารหัสใน output
exit: 0 = PASS หรือ SKIP ; 1-99 = จำนวน smoke FAIL ; 100 = หยุดกลางทาง (ข้อความขึ้นต้น FAIL)
  -PlanOnly : อ่าน config + ตรวจ Targets/MSI แล้วบอกว่าจะทำอะไร ไม่แก้เครื่อง
#>
param(
    [string]$ConfigPath = "${env:ProgramFiles(x86)}\ossec-agent\shared\ssjmuk-vnc.SECRET",
    [string]$Msi = (Join-Path $PSScriptRoot 'vnc\tightvnc-2.8.85-gpl-setup-64bit.msi'),
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'
$MsiSha256 = 'D8FBED7B27EBAB86DF6F780F6E86F723668F3715CEE521CCAA4568812AEF5F3E'
$RegPath   = 'HKLM:\SOFTWARE\TightVNC\Server'
$RegNet    = 'HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server'
$FwName    = 'SSJMUK VNC helpdesk'
$SvcName   = 'tvnserver'
$script:Changed = $false

function Read-VncConfig {
    $cfg = @{}
    foreach ($line in Get-Content -Path $ConfigPath) {
        if ($line -match '^\s*(\w+)\s*=\s*(.*?)\s*$') { $cfg[$Matches[1]] = $Matches[2] }
    }
    foreach ($k in 'Password', 'Port', 'Helpdesk', 'Targets') { if (-not $cfg[$k]) { throw "config ขาด $k" } }
    if ($cfg.Password -notmatch '^([0-9a-fA-F]{2})+$') { throw 'config Password ไม่ใช่ hex' }
    if ($cfg.ControlPassword -and $cfg.ControlPassword -notmatch '^([0-9a-fA-F]{2})+$') { throw 'config ControlPassword ไม่ใช่ hex' }
    $port = 0
    if (-not [int]::TryParse($cfg.Port, [ref]$port) -or $port -lt 10000 -or $port -gt 49151) { throw 'config Port ต้องเป็น 10000-49151' }
    $helpdesk = @($cfg.Helpdesk -split '\s*,\s*' | Where-Object { $_ })
    foreach ($h in $helpdesk) {
        $ip = $null
        if ($h -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or -not [Net.IPAddress]::TryParse($h, [ref]$ip)) { throw "config Helpdesk '$h' ไม่ใช่ IP เดี่ยว" }
    }
    [pscustomobject]@{
        Password        = $cfg.Password
        ControlPassword = $cfg.ControlPassword
        Port            = $port
        Helpdesk        = $helpdesk
        Targets         = @($cfg.Targets -split '\s*,\s*' | Where-Object { $_ })
        # helpdesk = 2 (ถามผู้ใช้ก่อนรับ) ; IP อื่นทั้งหมด = 1 (ปฏิเสธ) — รูปแบบนี้ยืนยันแล้วว่ามีหน้าต่างถาม (pilot 13 พ.ย. 2569)
        Acl             = (@($helpdesk | ForEach-Object { "$_-$($_):2" }) + '0.0.0.0-255.255.255.255:1') -join ','
    }
}

function ConvertFrom-Hex([string]$Hex) {
    $b = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
    , $b
}

function Get-ExcludedRanges {
    # * ท้ายบรรทัด = administered (จองด้วย netsh add) ; ไม่มี * = ระบบจอง เช่น Hyper-V/winnat ซึ่ง bind ไม่ได้
    netsh int ipv4 show excludedportrange protocol=tcp | Select-String '^\s*(\d+)\s+(\d+)(\s+\*)?' | ForEach-Object {
        $g = $_.Matches[0].Groups
        [pscustomobject]@{ Start = [int]$g[1].Value; End = [int]$g[2].Value; Admin = $g[3].Success }
    }
}

function Get-OtherVncAllowRules {
    # rule allow ขาเข้าของ TightVNC ที่ไม่ใช่ rule จำกัด IP ของเรา (Viewer/MSI บางรุ่นสร้างให้ทุก IP)
    $byProgram = Get-NetFirewallApplicationFilter -All | Where-Object { $_.Program -like '*\TightVNC\tvn*.exe' } | Get-NetFirewallRule
    $byName = Get-NetFirewallRule -DisplayName '*TightVNC*' -ErrorAction SilentlyContinue
    @($byProgram) + @($byName) | Where-Object {
        $_ -and $_.DisplayName -ne $FwName -and $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'
    } | Sort-Object Name -Unique
}

function Get-BroadAllowRules {
    # rule allow ขาเข้าที่ไม่จำกัดอะไรเลย (port/IP/program/service = Any) เปิด port VNC ให้ทุกคนข้าม rule จำกัด IP ของเรา
    $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)
    if (-not $rules.Count) { return @() }
    $port = @{}; Get-NetFirewallPortFilter -All | ForEach-Object { $port[$_.InstanceID] = $_ }
    $addr = @{}; Get-NetFirewallAddressFilter -All | ForEach-Object { $addr[$_.InstanceID] = $_ }
    $app  = @{}; Get-NetFirewallApplicationFilter -All | ForEach-Object { $app[$_.InstanceID] = $_ }
    $svc  = @{}; Get-NetFirewallServiceFilter -All | ForEach-Object { $svc[$_.InstanceID] = $_ }
    $rules | Where-Object {
        $id = $_.InstanceID; $p = $port[$id]
        $p -and ($p.Protocol -in 'Any', 'TCP') -and (@($p.LocalPort) -contains 'Any') -and
        (@($addr[$id].RemoteAddress) -contains 'Any') -and $app[$id].Program -eq 'Any' -and $svc[$id].Service -eq 'Any'
    }
}

function Test-RegValue([string]$Name) {
    $k = Get-Item $RegPath -ErrorAction SilentlyContinue
    [bool]($k -and ($k.GetValueNames() -contains $Name))
}

function Test-Prereq($Cfg) {
    $hit = Get-ExcludedRanges | Where-Object { -not $_.Admin -and $Cfg.Port -ge $_.Start -and $Cfg.Port -le $_.End } | Select-Object -First 1
    if ($hit) { throw "Port $($Cfg.Port) อยู่ในช่วงที่ระบบจอง $($hit.Start)-$($hit.End)" }
    $used = Get-NetTCPConnection -LocalPort $Cfg.Port -State Listen -ErrorAction SilentlyContinue | Where-Object {
        (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -ne $SvcName
    } | Select-Object -First 1
    if ($used) { throw "Port $($Cfg.Port) มีโปรแกรมอื่นฟังอยู่ (PID $($used.OwningProcess))" }
    $off = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'False' })
    if ($off.Count) { throw "Windows Firewall ปิดอยู่ใน profile: $($off.Name -join ', ') -> ไม่ติดตั้ง (rule จำกัด IP จะไม่มีผล)" }
}

function Set-PortReservation([int]$Port) {
    # บางเครื่อง dynamic port กว้างผิดปกติ (เช่น 1024-65535) Windows อาจสุ่ม $Port เป็น port ขาออกก่อน tvnserver เปิดตอน boot
    # ; การจองแบบ administered ไม่กัน tvnserver bind (ยืนยันจาก pilot 2 เครื่อง)
    if (Get-ExcludedRanges | Where-Object { $_.Admin -and $Port -ge $_.Start -and $Port -le $_.End }) { return }
    netsh int ipv4 add excludedportrange protocol=tcp startport=$Port numberofports=1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "จอง port $Port ไม่สำเร็จ (netsh exit $LASTEXITCODE)" }
    Write-Host "  จอง port $Port"
}

function Install-Server {
    if (-not (Test-Path $Msi)) { throw "ไม่พบ MSI $Msi" }
    $hash = (Get-FileHash $Msi -Algorithm SHA256).Hash
    if ($hash -ne $MsiSha256) { throw "SHA256 MSI ไม่ตรงค่าที่ pin ($hash)" }
    $sig = Get-AuthenticodeSignature $Msi
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*GlavSoft*') { throw "ลายเซ็น MSI ไม่ผ่าน ($($sig.Status))" }
    # ค่า server เขียน registry เองใน Set-ServerConfig ; MSI รับแค่ส่วนที่ต้องทำตอนติดตั้ง
    $msiArgs = "/i `"$Msi`" /quiet /norestart ADDLOCAL=Server SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=0"
    $code = (Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru).ExitCode
    if ($code -notin 0, 3010) { throw "msiexec exit $code" }
    Write-Host "  ติดตั้ง TightVNC Server (msiexec exit $code)"
    $script:Changed = $true
}

function Set-RegIfDiff([string]$Name, $Value, [string]$Type) {
    $cur = (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ("$cur" -ne "$Value") {
        Set-ItemProperty -Path $RegPath -Name $Name -Value $Value -Type $Type
        Write-Host "  ตั้ง $Name"
        $script:Changed = $true
    }
}

function Set-SecretIfDiff([string]$Name, [string]$Hex) {
    $want = ConvertFrom-Hex $Hex
    $cur = [Microsoft.Win32.Registry]::GetValue($RegNet, $Name, $null)
    if (($cur -is [byte[]]) -and ([Convert]::ToBase64String($cur) -eq [Convert]::ToBase64String($want))) { return }
    # เขียนผ่าน .NET ไม่ใช้ Set-ItemProperty : PowerShell module logging (EID 4103) บันทึกค่า parameter ของ cmdlet
    [Microsoft.Win32.Registry]::SetValue($RegNet, $Name, $want, [Microsoft.Win32.RegistryValueKind]::Binary)
    Write-Host "  ตั้ง $Name (ไม่แสดงค่า)"
    $script:Changed = $true
}

function Set-ServerConfig($Cfg) {
    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
    Set-RegIfDiff RfbPort $Cfg.Port DWord
    Set-RegIfDiff AcceptHttpConnections 0 DWord
    Set-RegIfDiff UseVncAuthentication 1 DWord
    Set-RegIfDiff QueryTimeout 30 DWord
    Set-RegIfDiff QueryAcceptOnTimeout 0 DWord
    Set-RegIfDiff IpAccessControl $Cfg.Acl String
    Set-SecretIfDiff Password $Cfg.Password
    if ($Cfg.ControlPassword) {
        Set-SecretIfDiff ControlPassword $Cfg.ControlPassword
        Set-RegIfDiff UseControlAuthentication 1 DWord
    }
}

function Set-Firewall($Cfg) {
    $rule = Get-NetFirewallRule -DisplayName $FwName -ErrorAction SilentlyContinue
    $want = (@($Cfg.Helpdesk) | Sort-Object) -join ','
    if ($rule) {
        $addr = (@(($rule | Get-NetFirewallAddressFilter).RemoteAddress) | Sort-Object) -join ','
        $pf = $rule | Get-NetFirewallPortFilter
        if ($addr -ne $want -or "$($pf.LocalPort)" -ne "$($Cfg.Port)" -or $pf.Protocol -ne 'TCP' -or $rule.Enabled -ne 'True' -or $rule.Action -ne 'Allow') {
            Set-NetFirewallRule -DisplayName $FwName -Protocol TCP -LocalPort $Cfg.Port -RemoteAddress $Cfg.Helpdesk -Action Allow -Enabled True
            Write-Host '  แก้ firewall rule'
        }
    } else {
        New-NetFirewallRule -DisplayName $FwName -Direction Inbound -Protocol TCP -LocalPort $Cfg.Port -RemoteAddress $Cfg.Helpdesk -Action Allow -Profile Any | Out-Null
        Write-Host '  สร้าง firewall rule'
    }
    foreach ($r in Get-OtherVncAllowRules) {
        Disable-NetFirewallRule -Name $r.Name
        Write-Host "  ปิด rule allow ที่ไม่จำกัด IP: $($r.DisplayName)"
    }
}

function Invoke-Smoke($Cfg) {
    $r      = Get-ItemProperty $RegPath -ErrorAction SilentlyContinue
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in $Cfg.Port, 5900, 5800 } | Select-Object -ExpandProperty LocalPort -Unique)
    $fw     = Get-NetFirewallRule -DisplayName $FwName -ErrorAction SilentlyContinue
    $fwAddr = if ($fw) { (@(($fw | Get-NetFirewallAddressFilter).RemoteAddress) | Sort-Object) -join ',' } else { '' }
    $fwPort = if ($fw) { ($fw | Get-NetFirewallPortFilter).LocalPort } else { '' }
    $broad  = @(Get-BroadAllowRules)
    $checks = [ordered]@{
        'service tvnserver Running'               = (Get-Service $SvcName -ErrorAction SilentlyContinue).Status -eq 'Running'
        'RfbPort ตรง config'                         = $r.RfbPort -eq $Cfg.Port
        'listen port config และไม่ listen 5900/5800' = ($listen -contains $Cfg.Port) -and ($listen -notcontains 5900) -and ($listen -notcontains 5800)
        'AcceptHttpConnections = 0'                = $r.AcceptHttpConnections -eq 0
        'IpAccessControl ตรง config'                = $r.IpAccessControl -eq $Cfg.Acl
        'QueryAcceptOnTimeout = 0'                 = $r.QueryAcceptOnTimeout -eq 0
        'ตั้งรหัสแล้ว (UseVncAuthentication = 1)'     = (Test-RegValue 'Password') -and $r.UseVncAuthentication -eq 1
        'ตั้ง control password แล้ว'                 = (-not $Cfg.ControlPassword) -or ((Test-RegValue 'ControlPassword') -and $r.UseControlAuthentication -eq 1)
        'firewall rule จำกัดเฉพาะ helpdesk'          = [bool]$fw -and $fwAddr -eq ((@($Cfg.Helpdesk) | Sort-Object) -join ',') -and "$fwPort" -eq "$($Cfg.Port)"
        'ไม่มี rule allow อื่นของ TightVNC'          = -not (Get-OtherVncAllowRules)
        "ไม่มี rule allow ขาเข้าแบบกว้าง (พบ $($broad.Count))" = $broad.Count -eq 0
        'จอง port แล้ว (excludedportrange)'         = [bool](Get-ExcludedRanges | Where-Object { $_.Admin -and $Cfg.Port -ge $_.Start -and $Cfg.Port -le $_.End })
        'Windows Firewall เปิดทุก profile'           = -not (Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'False' })
    }
    $fail = 0
    foreach ($c in $checks.GetEnumerator()) {
        if ($c.Value) { Write-Host "PASS  $($c.Key)" } else { $fail++; Write-Host "FAIL  $($c.Key)" }
    }
    foreach ($b in $broad) { Write-Host "  rule กว้าง: $($b.DisplayName)" }
    if ($fail) { Write-Host "SUMMARY FAIL ($fail)" } else { Write-Host 'SUMMARY PASS' }
    $fail
}

try {
    if (-not (Test-Path $ConfigPath)) { Write-Host 'SKIP ไม่มี config (ยังไม่เปิดใช้ VNC กับ group นี้)'; exit 0 }
    $cfg = Read-VncConfig
    if (-not (($cfg.Targets -contains 'all') -or ($cfg.Targets -contains $env:COMPUTERNAME))) {
        Write-Host "SKIP $env:COMPUTERNAME ไม่อยู่ใน Targets"
        exit 0
    }
    $installed = [bool](Get-Service $SvcName -ErrorAction SilentlyContinue)
    if ($PlanOnly) {
        Write-Host "PLAN target=yes installed=$installed msi=$(Test-Path $Msi) helpdesk=$($cfg.Helpdesk.Count) controlPassword=$([bool]$cfg.ControlPassword)"
        exit 0
    }
    Test-Prereq $cfg
    Set-PortReservation $cfg.Port
    if (-not $installed) { Install-Server }
    Set-ServerConfig $cfg
    Set-Firewall $cfg
    if ($script:Changed) {
        Restart-Service $SvcName
        Write-Host '  restart tvnserver'
    } elseif ((Get-Service $SvcName).Status -ne 'Running') {
        Start-Service $SvcName
        Write-Host '  start tvnserver'
    }
    exit (Invoke-Smoke $cfg)
} catch {
    Write-Host "FAIL $($_.Exception.Message)"
    exit 100
}
# EOF-SENTINEL-SSJMUK
