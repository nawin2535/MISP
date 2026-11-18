<#
deploy-vnc.ps1 - ติดตั้ง/ดูแล TightVNC Server สำหรับ helpdesk (เรียกจาก ssjmuk-task.ps1 Step 9 ; รันเป็น SYSTEM)

repo นี้เป็น public: ไฟล์นี้ไม่มีรหัส / IP / port / รายชื่อเครื่อง
ค่าทั้งหมดอ่านจาก ssjmuk-vnc.SECRET ที่ Wazuh manager ส่งมาใน shared ของ agent group (อ่านได้เฉพาะ admin/SYSTEM)
  Password=<hex> ControlPassword=<hex> Port=<10000-49151> Helpdesk=<ip,ip> Targets=<IP / a.b.c.* / COMPUTERNAME,...|all>
  [FirewallEnable=<รูปแบบเดียวกับ Targets>] [FirewallExclude=<รูปแบบเดียวกับ Targets>]
การตัดสินว่าเครื่องอยู่ใน Targets มีที่นี่ที่เดียว (ssjmuk-task.ps1 Step 9 เรียก -PlanOnly ก่อนโหลด MSI)
  Targets = ใครได้ติดตั้งใหม่ ; เครื่องที่ติดตั้งแล้ว (managed) แต่ตอนรันไม่อยู่ใน Targets ยัง sync config/firewall
  โดยไม่ start service ที่หยุดไว้ ; SUMMARY ต่อท้าย "- managed (not in Targets)"

ห้ามมีขั้นโต้ตอบ (SYSTEM / session 0) ; ไม่แสดงค่ารหัสใน output
output เป็นภาษาอังกฤษ: ssjmuk-task อ่าน stdout ของ process ลูกด้วย codepage ของเครื่อง ภาษาไทยจะเพี้ยนใน log
exit: 0 = PASS หรือ SKIP ; 1-99 = จำนวน smoke FAIL ; 100 = หยุดกลางทาง (ข้อความขึ้นต้น FAIL)
  Windows Firewall ปิดบาง profile = ติดตั้งต่อ ; อยู่ใน FirewallEnable และไม่อยู่ใน FirewallExclude = เปิดให้ครั้งเดียว
  ต่อท้าย SUMMARY ด้วยสถานะ firewall (มีคำว่า WARN = การ์ด Discord ขึ้นไอคอนเตือน) ไม่เปลี่ยน exit
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
$MarkPath  = 'HKLM:\SOFTWARE\SSJMUK\VncHelpdesk'
# เวลาใน marker / SUMMARY: เครื่อง locale ไทยจะได้ปี พ.ศ. ถ้าใช้ culture ของเครื่อง
$Inv       = [Globalization.CultureInfo]::InvariantCulture
$script:Changed = $false

function Read-VncConfig {
    $cfg = @{}
    foreach ($line in Get-Content -Path $ConfigPath) {
        if ($line -match '^\s*(\w+)\s*=\s*(.*?)\s*$') { $cfg[$Matches[1]] = $Matches[2] }
    }
    foreach ($k in 'Password', 'Port', 'Helpdesk', 'Targets') { if (-not $cfg[$k]) { throw "config missing $k" } }
    if ($cfg.Password -notmatch '^([0-9a-fA-F]{2})+$') { throw 'config Password is not hex' }
    if ($cfg.ControlPassword -and $cfg.ControlPassword -notmatch '^([0-9a-fA-F]{2})+$') { throw 'config ControlPassword is not hex' }
    $port = 0
    if (-not [int]::TryParse($cfg.Port, [ref]$port) -or $port -lt 10000 -or $port -gt 49151) { throw 'config Port must be 10000-49151' }
    $helpdesk = @($cfg.Helpdesk -split '\s*,\s*' | Where-Object { $_ })
    foreach ($h in $helpdesk) {
        $ip = $null
        if ($h -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or -not [Net.IPAddress]::TryParse($h, [ref]$ip)) { throw "config Helpdesk '$h' is not a single IPv4" }
    }
    [pscustomobject]@{
        Password        = $cfg.Password
        ControlPassword = $cfg.ControlPassword
        Port            = $port
        Helpdesk        = $helpdesk
        Targets         = @($cfg.Targets -split '\s*,\s*' | Where-Object { $_ })
        # ไม่มีคีย์ = ไม่เปิด firewall ให้ใคร (รายงานอย่างเดียว) ; Exclude ชนะ Enable
        FirewallEnable  = @("$($cfg.FirewallEnable)" -split '\s*,\s*' | Where-Object { $_ })
        FirewallExclude = @("$($cfg.FirewallExclude)" -split '\s*,\s*' | Where-Object { $_ })
        # helpdesk = 2 (ถามผู้ใช้ก่อนรับ) ; IP อื่นทั้งหมด = 1 (ปฏิเสธ) — รูปแบบนี้ยืนยันแล้วว่ามีหน้าต่างถาม (pilot 13 พ.ย. 2569)
        Acl             = (@($helpdesk | ForEach-Object { "$_-$($_):2" }) + '0.0.0.0-255.255.255.255:1') -join ','
    }
}

function Test-HostMatch([string[]]$List) {
    # IP ทุกเครื่อง reserve ไว้แล้ว -> ใช้ IP / wildcard ได้ ; ชื่อเครื่องยังใช้ได้
    if (-not $List) { return $false }
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
    foreach ($t in $List) {
        if ($t -eq 'all' -or $t -eq $env:COMPUTERNAME) { return $true }
        foreach ($ip in $ips) { if ($ip -like $t) { return $true } }
    }
    $false
}

function Test-Target($Cfg) { Test-HostMatch $Cfg.Targets }

function Test-Managed {
    # ติดตั้งแล้ว + มี rule ของเรา = อยู่ในฟลีต VNC แม้ตอนรัน IP ไม่อยู่ใน Targets (เช่นโน้ตบุ๊กนอก office)
    # -> ยัง sync config ไม่อย่างนั้นถอด IP helpdesk / เปลี่ยนรหัสแล้วเครื่องนี้ค้างค่าเก่า (15 พ.ย. 2569)
    [bool](Get-Service $SvcName -ErrorAction SilentlyContinue) -and [bool](Get-NetFirewallRule -DisplayName $FwName -ErrorAction SilentlyContinue)
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
    # rule ของแอป Store/UWP (Teams, Xbox ...) = network isolation มีผลกับ AppContainer ของแอปนั้นเท่านั้น -> ไม่นับ
    # ระบุได้จาก Package (application filter) หรือ Owner (SID ผู้ติดตั้งแอป) ; rule ที่ installer/admin สร้างไม่มีทั้งคู่
    # (13 พ.ย. 2569: ไม่กรอง = 39 rule, กรอง Package อย่างเดียว = 31 ที่เหลือมีแต่ Owner)
    $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)
    if (-not $rules.Count) { return @() }
    $port = @{}; Get-NetFirewallPortFilter -All | ForEach-Object { $port[$_.InstanceID] = $_ }
    $addr = @{}; Get-NetFirewallAddressFilter -All | ForEach-Object { $addr[$_.InstanceID] = $_ }
    $app  = @{}; Get-NetFirewallApplicationFilter -All | ForEach-Object { $app[$_.InstanceID] = $_ }
    $svc  = @{}; Get-NetFirewallServiceFilter -All | ForEach-Object { $svc[$_.InstanceID] = $_ }
    $rules | Where-Object {
        $id = $_.InstanceID; $p = $port[$id]; $a = $app[$id]
        $p -and ($p.Protocol -in 'Any', 'TCP') -and (@($p.LocalPort) -contains 'Any') -and
        (@($addr[$id].RemoteAddress) -contains 'Any') -and $a.Program -eq 'Any' -and -not $a.Package -and
        -not $_.Owner -and $svc[$id].Service -eq 'Any'
    }
}

function Test-RegValue([string]$Name) {
    $k = Get-Item $RegPath -ErrorAction SilentlyContinue
    [bool]($k -and ($k.GetValueNames() -contains $Name))
}

function Test-Prereq($Cfg) {
    $hit = Get-ExcludedRanges | Where-Object { -not $_.Admin -and $Cfg.Port -ge $_.Start -and $Cfg.Port -le $_.End } | Select-Object -First 1
    if ($hit) { throw "port $($Cfg.Port) is inside a system-reserved range $($hit.Start)-$($hit.End)" }
    $used = Get-NetTCPConnection -LocalPort $Cfg.Port -State Listen -ErrorAction SilentlyContinue | Where-Object {
        (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -ne $SvcName
    } | Select-Object -First 1
    if ($used) { throw "port $($Cfg.Port) is used by another process (PID $($used.OwningProcess))" }
}

function Get-FirewallOff {
    # ActiveStore = ค่าที่มีผลจริง (รวม policy) ; ไม่ระบุ store = อ่านแค่ค่า local
    @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Enabled -eq 'False' } | Select-Object -ExpandProperty Name)
}

function Get-ThirdPartyFirewall {
    # firewall ยี่ห้ออื่นที่เปิดอยู่จะปิด Windows Firewall กลับ -> ไม่เปิดซ้อน ; WatchGuard ของฟลีตลงทะเบียนเป็น AV อย่างเดียว
    # ยี่ห้อที่ค้างลงทะเบียนแต่ปิดอยู่ไม่นับ (เครื่อง admin มี McAfee 0x042000 แต่ Windows Firewall เปิด) ; productState byte กลาง bit 0x10 = เปิด
    try {
        @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop |
            Where-Object { (([int]$_.productState -shr 8) -band 0x10) -ne 0 } |
            ForEach-Object { "$($_.displayName)" -replace '[^\x20-\x7E]', '?' })
    } catch { @() }   # Windows Server ไม่มี SecurityCenter2
}

function Get-PolicyOff([string[]]$Profiles) {
    # policy (GPO / local) สั่งปิด = Set-NetFirewallProfile เปิดไม่ติด ; StandardProfile = policy รุ่นเก่าของเครื่องนอก domain
    $keys = @{ Domain = @('DomainProfile'); Private = @('PrivateProfile', 'StandardProfile'); Public = @('PublicProfile', 'StandardProfile') }
    @($Profiles | Where-Object {
        @($keys[$_] | Where-Object {
            (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$_" -Name EnableFirewall -ErrorAction SilentlyContinue).EnableFirewall -eq 0
        }).Count -gt 0
    })
}

function Get-FirewallDisabler($Since) {
    # event ล่าสุดที่ปิด firewall: 2082 (Win11) / 2003 (Win10) ; SettingType 1 = เปิด/ปิด firewall
    # ค่าปิด: Win11 SettingValueString=No ; Win10 ยังไม่ยืนยันชื่อฟิลด์ -> รับ SettingValue ที่เป็นศูนย์ด้วย ; ไม่เจอ = unknown
    # ส่งออกแค่ชื่อ exe + เวลา : path เต็มอาจมีชื่อ user และ ModifyingUser เป็น SID
    try {
        $f = @{ LogName = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Id = 2003, 2082 }
        if ($Since) { $f.StartTime = $Since }
        foreach ($e in @(Get-WinEvent -FilterHashtable $f -MaxEvents 200 -ErrorAction SilentlyContinue)) {
            $d = @{}
            foreach ($x in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$x.Name] = "$($x.'#text')" }
            $val = if ($d['SettingValueString']) { $d['SettingValueString'] } else { $d['SettingValue'] }
            if ($d['SettingType'] -ne '1' -or $val -notmatch '^(No|False|(0x)?0+)$') { continue }
            $exe = ("$($d['ModifyingApplication'])" -replace '^.*\\', '') -replace '[^\x20-\x7E]', '?'
            if (-not $exe) { $exe = 'unknown-app' }
            return "$exe $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm', $Inv))"
        }
        'unknown (no event)'
    } catch { 'unknown (event read failed)' }
}

function Get-FwMark {
    $v = (Get-ItemProperty $MarkPath -Name FirewallEnabledAt -ErrorAction SilentlyContinue).FirewallEnabledAt
    $t = [datetime]::MinValue
    if ($v -and [datetime]::TryParseExact($v, 's', $Inv, [Globalization.DateTimeStyles]::None, [ref]$t)) { return $t }
    $null
}

function Set-FwMark {
    if (-not (Test-Path $MarkPath)) { New-Item -Path $MarkPath -Force | Out-Null }
    Set-ItemProperty -Path $MarkPath -Name FirewallEnabledAt -Value ((Get-Date).ToString('s', $Inv)) -Type String
}

function Write-ListenSnapshot {
    # port ที่เครื่องอื่นต่อเข้าได้ก่อนเปิด firewall (ลง log ของเครื่อง) -> เทียบเมื่อมีคนแจ้งว่าแชร์/ปริ้นเตอร์/โปรแกรมใช้ไม่ได้
    $rows = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' } |
        ForEach-Object { [pscustomobject]@{ P = [int]$_.LocalPort; N = "$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name)" -replace '[^\x20-\x7E]', '?' } } |
        Sort-Object P, N -Unique | ForEach-Object { "$($_.P)/$($_.N)" }
    Write-Host "  listening before enable: $(@($rows) -join ' ')"
}

function Invoke-FirewallEnable($Cfg) {
    # 14 พ.ย. 2569 แค่รายงาน WARN ให้ helpdesk เปิดเอง -> 18 พ.ย. user ให้สคริปต์เปิดให้ ไล่วงด้วย FirewallEnable
    # ยกเว้น FirewallExclude (เครื่องแชร์ printer/file, เครื่อง admin IT) ; rule helpdesk สร้างแล้วใน Set-Firewall -> เปิดแล้ว VNC ยังเข้าได้
    # เปิดครั้งเดียวต่อเครื่อง: ถูกปิดกลับหลังเราเปิด = ไม่เปิดซ้ำ รายงานว่าโปรแกรมไหนปิด
    # (เปิดซ้ำทุกวัน = โปรแกรมที่ต้องปิด firewall พังทุกเช้า และกลบหลักฐาน)
    # คืนข้อความต่อท้าย SUMMARY ; '' = firewall เปิดครบ
    $off = @(Get-FirewallOff)
    if (-not $off.Count) { return '' }
    $p = $off -join ', '
    if (Test-HostMatch $Cfg.FirewallExclude) { return "firewall off (excluded): $p" }
    $mark = Get-FwMark
    if ($mark) { return "WARN firewall re-disabled: $p by $(Get-FirewallDisabler $mark)" }
    $other = @(Get-ThirdPartyFirewall)
    if ($other.Count) { return "WARN firewall off: $p (3rd-party firewall on: $($other -join '/'))" }
    $pol = @(Get-PolicyOff $off)
    if ($pol.Count) { return "WARN firewall off by policy: $($pol -join ', ')" }
    if (-not (Test-HostMatch $Cfg.FirewallEnable)) { return "WARN firewall off: $p" }
    $who = Get-FirewallDisabler $null
    Write-ListenSnapshot
    try {
        Set-NetFirewallProfile -Profile $off -Enabled True
    } catch {
        Write-Host "  firewall enable error HRESULT $($_.Exception.HResult)"
        return "WARN firewall enable failed: $p"
    }
    $still = @(Get-FirewallOff)
    if ($still.Count) { return "WARN firewall enable failed: $($still -join ', ')" }
    Set-FwMark
    Write-Host "  enabled Windows Firewall: $p"
    "firewall enabled: $p (was off by $who)"
}

function Format-Summary([int]$Fail, [string]$Fw = '', [string]$Note = '') {
    $s = if ($Fail) { "SUMMARY FAIL ($Fail)" } else { 'SUMMARY PASS' }
    if ($Fw) { $s += " - $Fw" }
    if ($Note) { $s += " - $Note" }
    $s
}

function Set-PortReservation([int]$Port) {
    # บางเครื่อง dynamic port กว้างผิดปกติ (เช่น 1024-65535) Windows อาจสุ่ม $Port เป็น port ขาออกก่อน tvnserver เปิดตอน boot
    # ; การจองแบบ administered ไม่กัน tvnserver bind (ยืนยันจาก pilot 2 เครื่อง)
    if (Get-ExcludedRanges | Where-Object { $_.Admin -and $Port -ge $_.Start -and $Port -le $_.End }) { return }
    netsh int ipv4 add excludedportrange protocol=tcp startport=$Port numberofports=1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "port $Port reservation failed (netsh exit $LASTEXITCODE)" }
    Write-Host "  reserved port $Port"
}

function Install-Server {
    if (-not (Test-Path $Msi)) { throw "MSI not found: $Msi" }
    $hash = (Get-FileHash $Msi -Algorithm SHA256).Hash
    if ($hash -ne $MsiSha256) { throw "MSI SHA256 does not match pinned value ($hash)" }
    $sig = Get-AuthenticodeSignature $Msi
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*GlavSoft*') { throw "MSI signature check failed ($($sig.Status))" }
    # ค่า server เขียน registry เองใน Set-ServerConfig ; MSI รับแค่ส่วนที่ต้องทำตอนติดตั้ง
    $msiArgs = "/i `"$Msi`" /quiet /norestart ADDLOCAL=Server SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=0"
    $code = (Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru).ExitCode
    if ($code -notin 0, 3010) { throw "msiexec exit $code" }
    Write-Host "  installed TightVNC Server (msiexec exit $code)"
    $script:Changed = $true
}

function Set-RegIfDiff([string]$Name, $Value, [string]$Type) {
    $cur = (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ("$cur" -ne "$Value") {
        Set-ItemProperty -Path $RegPath -Name $Name -Value $Value -Type $Type
        Write-Host "  set $Name"
        $script:Changed = $true
    }
}

function Set-SecretIfDiff([string]$Name, [string]$Hex) {
    $want = ConvertFrom-Hex $Hex
    $cur = [Microsoft.Win32.Registry]::GetValue($RegNet, $Name, $null)
    if (($cur -is [byte[]]) -and ([Convert]::ToBase64String($cur) -eq [Convert]::ToBase64String($want))) { return }
    # เขียนผ่าน .NET ไม่ใช้ Set-ItemProperty : PowerShell module logging (EID 4103) บันทึกค่า parameter ของ cmdlet
    [Microsoft.Win32.Registry]::SetValue($RegNet, $Name, $want, [Microsoft.Win32.RegistryValueKind]::Binary)
    Write-Host "  set $Name (value not shown)"
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
            Write-Host '  updated firewall rule'
        }
    } else {
        New-NetFirewallRule -DisplayName $FwName -Direction Inbound -Protocol TCP -LocalPort $Cfg.Port -RemoteAddress $Cfg.Helpdesk -Action Allow -Profile Any | Out-Null
        Write-Host '  created firewall rule'
    }
    foreach ($r in Get-OtherVncAllowRules) {
        Disable-NetFirewallRule -Name $r.Name
        Write-Host "  disabled unrestricted TightVNC allow rule: $($r.DisplayName)"
    }
}

function Invoke-Smoke($Cfg, [bool]$Target, [string]$FwNote) {
    # ห้ามตั้งชื่อ parameter เป็น $Fw : ตัวแปร PowerShell ไม่แยกตัวพิมพ์ ชน $fw (rule) ข้างล่าง -> rule ถูกแปลงเป็น string (18 พ.ย. 2569)
    $svcUp  = (Get-Service $SvcName -ErrorAction SilentlyContinue).Status -eq 'Running'
    $r      = Get-ItemProperty $RegPath -ErrorAction SilentlyContinue
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in $Cfg.Port, 5900, 5800 } | Select-Object -ExpandProperty LocalPort -Unique)
    $fw     = Get-NetFirewallRule -DisplayName $FwName -ErrorAction SilentlyContinue
    $fwAddr = if ($fw) { (@(($fw | Get-NetFirewallAddressFilter).RemoteAddress) | Sort-Object) -join ',' } else { '' }
    $fwPort = if ($fw) { ($fw | Get-NetFirewallPortFilter).LocalPort } else { '' }
    $broad  = @(Get-BroadAllowRules)
    $checks = [ordered]@{
        'service tvnserver running'                   = $svcUp
        'RfbPort matches config'                      = $r.RfbPort -eq $Cfg.Port
        'listening on config port, not 5900/5800'     = ($listen -contains $Cfg.Port) -and ($listen -notcontains 5900) -and ($listen -notcontains 5800)
        'AcceptHttpConnections = 0'                   = $r.AcceptHttpConnections -eq 0
        'IpAccessControl matches config'              = $r.IpAccessControl -eq $Cfg.Acl
        'QueryAcceptOnTimeout = 0'                    = $r.QueryAcceptOnTimeout -eq 0
        'password set (UseVncAuthentication = 1)'     = (Test-RegValue 'Password') -and $r.UseVncAuthentication -eq 1
        'control password set'                        = (-not $Cfg.ControlPassword) -or ((Test-RegValue 'ControlPassword') -and $r.UseControlAuthentication -eq 1)
        'firewall rule limited to helpdesk'           = [bool]$fw -and $fwAddr -eq ((@($Cfg.Helpdesk) | Sort-Object) -join ',') -and "$fwPort" -eq "$($Cfg.Port)"
        'no other TightVNC allow rule'                = -not (Get-OtherVncAllowRules)
        "no broad inbound allow rule (found $($broad.Count))" = $broad.Count -eq 0
        'port reserved (excludedportrange)'           = [bool](Get-ExcludedRanges | Where-Object { $_.Admin -and $Cfg.Port -ge $_.Start -and $Cfg.Port -le $_.End })
    }
    $note = ''
    if (-not $Target) {
        $note = 'managed (not in Targets)'
        if (-not $svcUp) {
            # managed ที่ service หยุดไว้ (เช่นเครื่อง admin ที่ใช้แค่ Viewer) ไม่ start ให้เอง -> ตรวจแค่ config
            $checks.Remove('service tvnserver running')
            $checks.Remove('listening on config port, not 5900/5800')
            $note += ', service stopped'
        }
    }
    $fail = 0
    foreach ($c in $checks.GetEnumerator()) {
        if ($c.Value) { Write-Host "PASS  $($c.Key)" } else { $fail++; Write-Host "FAIL  $($c.Key)" }
    }
    foreach ($b in $broad) { Write-Host "  broad rule: $($b.DisplayName)" }
    if ($FwNote -match 'WARN') { Write-Host "WARN  $FwNote - port guarded only by TightVNC IP filter + password + user prompt" }
    Write-Host (Format-Summary $fail $FwNote $note)
    $fail
}

try {
    if (-not (Test-Path $ConfigPath)) { Write-Host 'SKIP no config (VNC not enabled for this group)'; exit 0 }
    $cfg = Read-VncConfig
    $target = Test-Target $cfg
    if (-not $target -and -not (Test-Managed)) {
        Write-Host "SKIP $env:COMPUTERNAME not in Targets"
        exit 0
    }
    $installed = [bool](Get-Service $SvcName -ErrorAction SilentlyContinue)
    if ($PlanOnly) {
        $tag = if ($target) { 'yes' } else { 'no-managed' }
        $fw = if (Test-HostMatch $cfg.FirewallExclude) { 'exclude' } elseif (Test-HostMatch $cfg.FirewallEnable) { 'enable' } else { 'no' }
        Write-Host "PLAN target=$tag installed=$installed msi=$(Test-Path $Msi) helpdesk=$($cfg.Helpdesk.Count) controlPassword=$([bool]$cfg.ControlPassword) firewall=$fw"
        exit 0
    }
    Test-Prereq $cfg
    Set-PortReservation $cfg.Port
    if (-not $installed) { Install-Server }
    Set-ServerConfig $cfg
    Set-Firewall $cfg
    # ตรวจ/เปิด firewall ล้มเอง ไม่ให้ลาก sync config VNC ล้มตาม
    try { $fwText = Invoke-FirewallEnable $cfg } catch { $fwText = "WARN firewall check error HRESULT $($_.Exception.HResult)" }
    # managed นอก Targets: service ที่หยุดไว้ปล่อยหยุด ; รันอยู่ + ค่าเปลี่ยน = restart ให้ค่าใหม่มีผล
    $running = (Get-Service $SvcName).Status -eq 'Running'
    if ($script:Changed -and ($target -or $running)) {
        Restart-Service $SvcName
        Write-Host '  restarted tvnserver'
    } elseif ($target -and -not $running) {
        Start-Service $SvcName
        Write-Host '  started tvnserver'
    }
    exit (Invoke-Smoke $cfg $target $fwText)
} catch {
    # เลขบรรทัดขึ้นการ์ด Discord -> ไล่ปัญหาจากการ์ดได้เลยไม่ต้องเข้าเครื่อง
    Write-Host "FAIL $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    exit 100
}
# EOF-SENTINEL-SSJMUK
