# install-iis-prereqs.ps1
# Installs IIS role/features and required reverse-proxy extensions (URL Rewrite + ARR).

$ErrorActionPreference = "Stop"

function Info($m){ Write-Host "[INFO] $m" }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Err ($m){ Write-Host "[ERROR] $m" -ForegroundColor Red }

function Ensure-Feature([string]$name) {
  $f = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
  if ($f -and $f.State -eq "Enabled") { return }
  Info "Enabling Windows feature: $name"
  dism /online /enable-feature /featurename:$name /all /norestart | Out-Null
}

function Is-AppInstalled([string]$displayNamePattern) {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )
  foreach ($p in $paths) {
    $apps = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
    if ($apps | Where-Object { $_.DisplayName -match $displayNamePattern }) { return $true }
  }
  return $false
}

function Install-MsiFromUrls([string[]]$urls, [string]$outFile) {
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $outFile) | Out-Null
  foreach ($url in $urls) {
    try {
      Info "Downloading: $url"
      Invoke-WebRequest -Uri $url -OutFile $outFile
      if ((Test-Path $outFile) -and ((Get-Item $outFile).Length -gt 1000000)) {
        Info "Installing: $outFile"
        Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i","`"$outFile`"","/qn","/norestart") -Wait
        return $true
      }
    } catch {
      Warn "Failed from URL: $url"
    }
  }
  return $false
}

Info "Installing IIS prerequisites..."
$features = @(
  "IIS-WebServerRole","IIS-WebServer","IIS-CommonHttpFeatures","IIS-DefaultDocument",
  "IIS-StaticContent","IIS-HttpErrors","IIS-HttpRedirect","IIS-ApplicationDevelopment",
  "IIS-ISAPIExtensions","IIS-ISAPIFilter","IIS-ManagementConsole"
)
foreach ($f in $features) { Ensure-Feature $f }

$dlDir = Join-Path $env:ProgramData "LocalS3\downloads"
$rewriteMsi = Join-Path $dlDir "rewrite_amd64_en-US.msi"
$arrMsi = Join-Path $dlDir "requestRouter_x64.msi"

if (-not (Is-AppInstalled "IIS URL Rewrite")) {
  Info "IIS URL Rewrite not found. Installing..."
  $rewriteUrls = @(
    "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi",
    "https://www.iis.net/downloads/microsoft/url-rewrite"
  )
  if (-not (Install-MsiFromUrls -urls $rewriteUrls -outFile $rewriteMsi)) {
    Err "Failed to install IIS URL Rewrite automatically."
    exit 1
  }
} else {
  Info "IIS URL Rewrite already installed."
}

if (-not (Is-AppInstalled "Application Request Routing")) {
  Info "IIS ARR not found. Installing..."
  $arrUrls = @(
    "https://go.microsoft.com/fwlink/?LinkID=615136",
    "https://www.iis.net/downloads/microsoft/application-request-routing"
  )
  if (-not (Install-MsiFromUrls -urls $arrUrls -outFile $arrMsi)) {
    Err "Failed to install IIS ARR automatically."
    exit 1
  }
} else {
  Info "IIS ARR already installed."
}

Info "IIS prerequisites installed successfully."
