# test-misp-restsearch.ps1
# Probe MISP /attributes/restSearch endpoint.
# Loads MISP_URL / MISP_API_KEY / MISP_VERIFY_SSL from .env in the same folder.
#
# MISP supports two query styles:
#   GET  -> path-style filters in URL (default here)
#   POST -> plain /attributes/restSearch endpoint + JSON body
#
# Usage:
#   .\test-misp-restsearch.ps1                              # default: GET, ip-src, last 300d
#   .\test-misp-restsearch.ps1 -Type ip-dst -Days 30
#   .\test-misp-restsearch.ps1 -Method POST -Type sha256    # POST with JSON body
#   .\test-misp-restsearch.ps1 -Format json -Save out.json
#   .\test-misp-restsearch.ps1 -ShowRequest                 # debug: print URL + body

[CmdletBinding()]
param(
    [ValidateSet('GET','POST')]
    [string]$Method = 'GET',
    [string]$Type   = 'ip-src',
    [int]   $Days   = 300,
    [ValidateSet('text','json','csv')]
    [string]$Format = 'text',
    [int]   $ToIds  = 1,
    [string]$Save   = '',
    [switch]$ShowRequest,
    # Which time filter to use. Default 'attribute_timestamp' because
    # publish_timestamp returns stale IoCs whose parent event was re-published
    # even though the attribute itself hasn't been touched in months.
    [ValidateSet('attribute_timestamp','publish_timestamp','timestamp','event_timestamp')]
    [string]$FilterParam = 'attribute_timestamp'
)

$ErrorActionPreference = 'Stop'

# --- Load .env ---
$envFile = Join-Path $PSScriptRoot '.env'
if (-not (Test-Path $envFile)) { throw ".env not found at $envFile" }

$cfg = @{}
Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith('#') -or $line -notmatch '=') { return }
    $k, $v = $line -split '=', 2
    $cfg[$k.Trim()] = $v.Trim().Trim('"').Trim("'")
}

$MispUrl   = $cfg['MISP_URL']
$ApiKey    = $cfg['MISP_API_KEY']
$VerifySsl = $cfg['MISP_VERIFY_SSL']
if (-not $MispUrl) { throw 'MISP_URL not set in .env' }
if (-not $ApiKey)  { throw 'MISP_API_KEY not set in .env' }
$skipCert = ($VerifySsl -and $VerifySsl.ToLower() -in @('false','0','f','no'))

# --- Build URL + Body depending on Method ---
$base = $MispUrl.TrimEnd('/')
if ($Method -eq 'GET') {
    $url  = "$base/attributes/restSearch/returnFormat:$Format/type:$Type/to_ids:$ToIds/${FilterParam}:${Days}d"
    $body = $null
} else {
    $url  = "$base/attributes/restSearch"
    $bodyObj = @{
        returnFormat = $Format
        type         = $Type
        to_ids       = $ToIds
    }
    $bodyObj[$FilterParam] = "${Days}d"
    $body = $bodyObj | ConvertTo-Json -Compress
}

Write-Host "$Method $url" -ForegroundColor Cyan
Write-Host "verify_ssl=$VerifySsl  (skipCert=$skipCert)" -ForegroundColor DarkGray
if ($ShowRequest) {
    if ($body) { Write-Host "body: $body" -ForegroundColor DarkGray }
    Write-Host "Authorization: $($ApiKey.Substring(0,4))...$($ApiKey.Substring($ApiKey.Length-4))" -ForegroundColor DarkGray
}

# --- SSL skip for Windows PowerShell 5.1 ---
if ($skipCert -and $PSVersionTable.PSVersion.Major -lt 6) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) { return true; }
}
"@ -ErrorAction SilentlyContinue
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12,Tls13'
}

# --- Headers ---
$headers = @{
    'Authorization' = $ApiKey
    'Accept'        = if ($Format -eq 'json') { 'application/json' } else { 'text/plain' }
}
if ($Method -eq 'POST') { $headers['Content-Type'] = 'application/json' }

$irmArgs = @{
    Uri        = $url
    Method     = $Method
    Headers    = $headers
    TimeoutSec = 120
}
if ($body) { $irmArgs['Body'] = $body }
if ($skipCert -and $PSVersionTable.PSVersion.Major -ge 6) { $irmArgs['SkipCertificateCheck'] = $true }

$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $resp = Invoke-WebRequest @irmArgs
    $sw.Stop()
    $bodyOut = $resp.Content
    $lines = if ($bodyOut) { ($bodyOut -split "`n").Count } else { 0 }
    $bytes = if ($bodyOut) { [System.Text.Encoding]::UTF8.GetByteCount($bodyOut) } else { 0 }

    Write-Host "`nHTTP $($resp.StatusCode) - $($sw.ElapsedMilliseconds) ms - $bytes bytes - $lines line(s)" -ForegroundColor Green
    Write-Host '---- first 20 lines ----' -ForegroundColor DarkGray
    ($bodyOut -split "`n") | Select-Object -First 20 | ForEach-Object { Write-Host $_ }

    if ($Save) {
        Set-Content -Path $Save -Value $bodyOut -Encoding utf8
        Write-Host "`nSaved full body to $Save" -ForegroundColor Yellow
    }
}
catch {
    $sw.Stop()
    Write-Host "`nFAILED after $($sw.ElapsedMilliseconds) ms" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if ($_.Exception.Response) {
        $sc = [int]$_.Exception.Response.StatusCode
        Write-Host "HTTP $sc $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
        # try to read response body for clue
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $errBody = $reader.ReadToEnd()
            if ($errBody) {
                Write-Host '---- response body ----' -ForegroundColor DarkGray
                Write-Host ($errBody.Substring(0, [Math]::Min(500, $errBody.Length)))
            }
        } catch {}
    }
    exit 1
}
