function Get-ScriptCreatedContainers([string]$dockerCtx) {
  $result = @{}

  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"

  # Reliable path for newer runs (label-based)
  $rows = @(docker --context $dockerCtx ps -a --filter "label=$($Script:LocalS3Label)" --format "{{.Names}}`t{{.Image}}`t{{.Status}}`t{{.Ports}}" 2>$null)
  foreach ($r in $rows) {
    if ([string]::IsNullOrWhiteSpace($r)) { continue }
    $parts = $r -split "`t", 4
    if ($parts.Count -lt 4) { continue }
    $name = $parts[0].Trim()
    if (-not $name) { continue }
    $result[$name] = [PSCustomObject]@{
      Name = $name; Image = $parts[1].Trim(); Status = $parts[2].Trim(); Ports = $parts[3].Trim()
    }
  }

  # Legacy path for older runs (best effort)
  foreach ($legacyName in @("minio","nginx")) {
    $legacyRows = @(docker --context $dockerCtx ps -a --filter "name=^${legacyName}$" --format "{{.Names}}`t{{.Image}}`t{{.Status}}`t{{.Ports}}" 2>$null)
    foreach ($r in $legacyRows) {
      if ([string]::IsNullOrWhiteSpace($r)) { continue }
      $parts = $r -split "`t", 4
      if ($parts.Count -lt 4) { continue }
      $name = $parts[0].Trim()
      if (-not $name) { continue }
      if (-not $result.ContainsKey($name)) {
        $result[$name] = [PSCustomObject]@{
          Name = $name; Image = $parts[1].Trim(); Status = $parts[2].Trim(); Ports = $parts[3].Trim()
        }
      }
    }
  }

  $ErrorActionPreference = $prev
  return @($result.Values)
}

function Prompt-CleanupPreviousServers([string]$dockerCtx) {
  $existing = @(Get-ScriptCreatedContainers -dockerCtx $dockerCtx)
  if ($existing.Count -eq 0) { return }

  Warn "Found existing S3 containers from previous runs:"
  $existing | Sort-Object Name | Format-Table -AutoSize | Out-String | Write-Host

  $ans = (Read-Host "Delete these previous containers before creating a new server? (Y/n)").Trim().ToLowerInvariant()
  if ($ans -eq "" -or $ans -eq "y" -or $ans -eq "yes") {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    foreach ($c in $existing) {
      docker --context $dockerCtx rm -f $c.Name 2>$null | Out-Null
    }
    docker --context $dockerCtx network rm storage-net 2>$null | Out-Null
    docker --context $dockerCtx volume rm -f locals3-minio-data 2>$null | Out-Null
    $ErrorActionPreference = $prev
    Info "Previous containers were removed."
  } else {
    Warn "Keeping previous containers. This may cause port conflicts."
  }
}


function Has-ExistingLocalS3IISInstall {
  $exists = $false
  try {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    foreach ($siteName in @("LocalS3", "LocalS3-IIS", "LocalS3-Console")) {
      if (Test-Path "IIS:\Sites\$siteName") { $exists = $true; break }
    }
  } catch {}

  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  schtasks /Query /TN "LocalS3-MinIO" 1>$null 2>$null
  if ($LASTEXITCODE -eq 0) { $exists = $true }
  $ErrorActionPreference = $prev

  return $exists
}

function Remove-ExistingLocalS3IISInstall([string]$root, [switch]$DeleteData) {
  Info "Removing existing LocalS3 IIS installation..."
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"

  try {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    foreach ($siteName in @("LocalS3", "LocalS3-IIS", "LocalS3-Console")) {
      if (Test-Path "IIS:\Sites\$siteName") {
        Stop-Website -Name $siteName 2>$null | Out-Null
        Remove-Website -Name $siteName 2>$null | Out-Null
      }
    }
  } catch {}
  # Remove LocalS3 certs from cert store so reinstalls don't inherit stale or mismatched chains.
  Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.FriendlyName -in @("LocalS3-HTTPS","LocalS3 HTTPS","LocalS3 Root CA") -or
    ($_.Subject -eq "CN=localhost" -and $_.Issuer -eq $_.Subject)
  } | Remove-Item -Force -ErrorAction SilentlyContinue
  Get-ChildItem Cert:\LocalMachine\Root | Where-Object {
    $_.FriendlyName -in @("LocalS3-HTTPS","LocalS3 HTTPS","LocalS3 Root CA") -or
    ($_.Subject -eq "CN=localhost" -and $_.Issuer -eq $_.Subject)
  } | Remove-Item -Force -ErrorAction SilentlyContinue

  schtasks /End /TN "LocalS3-MinIO" 1>$null 2>$null | Out-Null
  schtasks /Delete /TN "LocalS3-MinIO" /F 1>$null 2>$null | Out-Null

  Get-Process -Name "minio" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  if ($root) {
    $configDir = Join-Path $root "config"
    $siteDir = Join-Path $root "iis-site"
    $consoleSiteDir = Join-Path $root "iis-console-site"
    $certDir = Join-Path $root "nginx\certs"
    if (Test-Path $configDir) {
      Warn "Deleting previous MinIO config state..."
      Remove-Item -Recurse -Force -Path $configDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    }
    if (Test-Path $siteDir) {
      Remove-Item -Recurse -Force -Path $siteDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $siteDir | Out-Null
    }
    if (Test-Path $consoleSiteDir) {
      Remove-Item -Recurse -Force -Path $consoleSiteDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $consoleSiteDir | Out-Null
    }
    if (Test-Path $certDir) {
      Remove-Item -Recurse -Force -Path $certDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $certDir | Out-Null
    }
  }
  $ErrorActionPreference = $prev
  Start-Sleep -Seconds 2
}

function Invoke-LocalS3DockerCleanup {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  Sanitize-DockerEnv
  $dockerCtx = Get-ActiveDockerContext
  Prompt-CleanupPreviousServers -dockerCtx $dockerCtx
  $ErrorActionPreference = $prev
}

function Invoke-LocalS3IISCleanup {
  param([string]$Root = (Join-Path $env:ProgramData "LocalS3\storage-server"))
  Remove-ExistingLocalS3IISInstall -root $Root
}
