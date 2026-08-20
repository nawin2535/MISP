# ============================================================================
# Install-FortiGateCA.ps1 - Install FortiGate SSL-inspection CA into Trusted Root
# ============================================================================
# Purpose: Trust the FortiGate deep-inspection CA on this machine so that
#          SSL/HTTPS deep inspection does NOT trigger certificate warnings.
#
# Safety : Refuses to install a certificate that is NOT a CA (Basic
#          Constraints CA:TRUE). A public server cert like *.moph.go.th is
#          NOT a CA and CANNOT be used for deep inspection - this guard stops
#          the wrong file from being deployed by mistake.
#
# Idempotent: If the CA (matched by thumbprint) is already in the machine
#             Trusted Root store, it does nothing and exits 0.
#
# Store  : Cert:\LocalMachine\Root  (machine-wide, needs Administrator/SYSTEM)
#
# Usage (local test on admin's own machine):
#   powershell -ExecutionPolicy Bypass -File .\Install-FortiGateCA.ps1 -CertPath .\Fortinet_CA_SSL.cer
#
# Usage (future client rollout via pull-fileserver task, runs as SYSTEM):
#   powershell -ExecutionPolicy Bypass -File .\Install-FortiGateCA.ps1 -CertUrl "https://<fileserver>/certs/Fortinet_CA_SSL.cer"
# ============================================================================

param(
    [string]$CertPath,
    [string]$CertUrl,
    [switch]$Force   # bypass the CA:TRUE guard (NOT recommended)
)

$ErrorActionPreference = "Stop"

#region Helpers
function Test-AdminPrivileges {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-IsCaCertificate {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    foreach ($ext in $Cert.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            return [bool]$ext.CertificateAuthority
        }
    }
    return $false
}
#endregion

#region Main
try {
    if (-not (Test-AdminPrivileges)) {
        Write-Output "ERROR: Must run as Administrator (or SYSTEM). Trusted Root is a machine store."
        exit 1
    }

    # --- Resolve certificate source ---
    $sourceFile = $null
    $tempFile   = $null
    if ($CertUrl) {
        $tempDir = "C:\temp"
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
        $tempFile = Join-Path $tempDir "fortigate-ca-download.cer"
        Write-Output "Downloading CA from: $CertUrl"
        Invoke-WebRequest -Uri $CertUrl -OutFile $tempFile -UseBasicParsing
        $sourceFile = $tempFile
    } elseif ($CertPath) {
        if (-not (Test-Path $CertPath)) {
            Write-Output "ERROR: CertPath not found: $CertPath"
            exit 1
        }
        $sourceFile = (Resolve-Path $CertPath).Path
    } else {
        Write-Output "ERROR: Provide -CertPath <file.cer> or -CertUrl <url>."
        exit 1
    }

    # --- Load certificate ---
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sourceFile)
    Write-Output "Loaded certificate:"
    Write-Output "  Subject   : $($cert.Subject)"
    Write-Output "  Issuer    : $($cert.Issuer)"
    Write-Output "  Thumbprint: $($cert.Thumbprint)"
    Write-Output "  NotAfter  : $($cert.NotAfter)"

    # --- SAFETY: must be a CA certificate ---
    $isCa = Get-IsCaCertificate -Cert $cert
    Write-Output "  Is CA     : $isCa"
    if (-not $isCa) {
        if ($Force) {
            Write-Output "WARNING: Not a CA cert, but -Force set. Proceeding anyway."
        } else {
            Write-Output "ERROR: This is NOT a CA certificate (Basic Constraints CA:FALSE)."
            Write-Output "       A server cert (e.g. *.moph.go.th) cannot be used for deep inspection."
            Write-Output "       Export the FortiGate CA (Fortinet_CA_SSL) instead. Aborting."
            exit 2
        }
    }

    # --- Idempotent check ---
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $existing = $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $cert.Thumbprint, $false)

    if ($existing.Count -gt 0) {
        Write-Output "OK: CA already present in LocalMachine\Root (thumbprint match). Nothing to do."
        $store.Close()
        if ($tempFile -and (Test-Path $tempFile)) { Remove-Item $tempFile -Force }
        exit 0
    }

    # --- Install ---
    $store.Add($cert)
    $store.Close()

    # --- Verify ---
    $verify = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $verify.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $found = $verify.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $cert.Thumbprint, $false)
    $verify.Close()

    if ($found.Count -gt 0) {
        Write-Output "SUCCESS: CA installed into LocalMachine\Root."
    } else {
        Write-Output "ERROR: Post-install verification failed (cert not found in store)."
        exit 3
    }

    if ($tempFile -and (Test-Path $tempFile)) { Remove-Item $tempFile -Force }
    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
#endregion

# EOF-SENTINEL-SSJMUK
