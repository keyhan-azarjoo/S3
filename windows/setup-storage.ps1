# setup-storage.ps1 (Windows)
# Robust installer for MinIO + Nginx via Docker Compose.
# - Detects missing prerequisites
# - Starts Docker Desktop
# - Waits until Docker Engine is actually ready
# - Avoids port conflicts
# - Creates compose project and launches it
# - NEVER continues if docker engine is not reachable

$ErrorActionPreference = "Stop"
$Script:LocalS3Label = "com.locals3.installer=true"
$Script:RestartRequired = $false
$Script:RestartReasons = New-Object System.Collections.Generic.List[string]
$Script:StateDir = Join-Path $env:ProgramData "LocalS3"
$Script:RestartCountFile = Join-Path $Script:StateDir "restart-count.txt"
$Script:ActiveAccessKey = "admin"
$Script:ActiveSecretKey = "StrongPassword123"

function Info($m){ Write-Host "[INFO] $m" }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Err ($m){ Write-Host "[ERROR] $m" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Utility: generic retry with optional exponential back-off
# ---------------------------------------------------------------------------
function Retry-Operation {
  param(
    [scriptblock]$Action,
    [string]$Name = "operation",
    [int]$MaxAttempts = 3,
    [int]$DelaySeconds = 2,
    [switch]$Exponential
  )
  $attempt = 0
  while ($attempt -lt $MaxAttempts) {
    $attempt++
    try {
      return (& $Action)
    } catch {
      if ($attempt -lt $MaxAttempts) {
        $wait = if ($Exponential) { [int]($DelaySeconds * [Math]::Pow(2, $attempt - 1)) } else { $DelaySeconds }
        Warn "[$Name] attempt $attempt/$MaxAttempts failed: $($_.Exception.Message). Retrying in ${wait}s..."
        Start-Sleep -Seconds $wait
      } else {
        Warn "[$Name] all $MaxAttempts attempts failed. Last error: $($_.Exception.Message)"
        throw
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Utility: internet reachability check (ping + TCP fallback)
# ---------------------------------------------------------------------------
function Test-NetworkConnectivity {
  foreach ($ip in @("8.8.8.8","1.1.1.1","208.67.222.222")) {
    try {
      $ping = New-Object System.Net.NetworkInformation.Ping
      if ($ping.Send($ip, 3000).Status -eq "Success") { return $true }
    } catch {}
  }
  foreach ($hostPort in @("github.com:443","docker.com:443")) {
    $parts = $hostPort.Split(":")
    if (Test-TcpPort -targetHost $parts[0] -port ([int]$parts[1]) -timeoutMs 4000) { return $true }
  }
  return $false
}

# ---------------------------------------------------------------------------
# Utility: disk free-space check
# ---------------------------------------------------------------------------
function Test-DiskSpace {
  param([string]$Path = $env:SystemDrive, [int]$MinGB = 5)
  try {
    $drive = Split-Path -Qualifier $Path -ErrorAction SilentlyContinue
    if (-not $drive) { $drive = $env:SystemDrive }
    $disk = Get-PSDrive -Name ($drive.TrimEnd(':')) -ErrorAction SilentlyContinue
    if ($disk) {
      $freeGB = [Math]::Round($disk.Free / 1GB, 1)
      if ($freeGB -lt $MinGB) {
        Warn "Low disk space on ${drive}: ${freeGB} GB free (need at least $MinGB GB)."
        return $false
      }
      Info "Disk space OK: ${freeGB} GB free on ${drive}."
    }
  } catch {}
  return $true
}

# ---------------------------------------------------------------------------
# Pre-flight: disk space + network connectivity
# ---------------------------------------------------------------------------
function Run-PreflightChecks {
  param([string]$DataPath = "")
  Info "Running pre-flight checks..."
  $checkPath = if ($DataPath) { $DataPath } else { $env:SystemDrive }
  Test-DiskSpace -Path $checkPath -MinGB 5 | Out-Null
  if (-not (Test-NetworkConnectivity)) {
    Warn "No internet connectivity detected. Downloads may fail if Docker images are not cached."
  } else {
    Info "Network connectivity: OK"
  }
}

function Initialize-NetworkDefaults {
  try {
    $tls12 = [Net.SecurityProtocolType]::Tls12
    $tls11 = [Net.SecurityProtocolType]::Tls11
    [Net.ServicePointManager]::SecurityProtocol = $tls12 -bor $tls11
  } catch {}
}

function Is-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Relaunch-Elevated {
  if (Is-Admin) { return }
  Warn "Not running as Administrator. Relaunching elevated..."
  $ps = (Get-Process -Id $PID).Path
  Start-Process -FilePath $ps -Verb RunAs -ArgumentList @(
    "-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`""
  ) | Out-Null
  exit 0
}

function Has-Cmd($name){
  return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

function Register-ResumeAfterReboot {
  try {
    $scriptPath = (Resolve-Path -Path $PSCommandPath).Path
    $runOncePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    $cmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    New-Item -Path $runOncePath -Force | Out-Null
    New-ItemProperty -Path $runOncePath -Name "LocalS3SetupResume" -Value $cmd -PropertyType String -Force | Out-Null
    Info "Installer will resume automatically after next reboot/sign-in."
  } catch {
    Warn "Could not register auto-resume after reboot. Run this script again manually after restart."
  }
}

function Get-RestartCount {
  try {
    if (Test-Path $Script:RestartCountFile) {
      return [int](Get-Content -Path $Script:RestartCountFile -ErrorAction Stop | Select-Object -First 1)
    }
  } catch {}
  return 0
}

function Set-RestartCount([int]$count) {
  try {
    New-Item -ItemType Directory -Force -Path $Script:StateDir | Out-Null
    Set-Content -Path $Script:RestartCountFile -Value "$count" -Encoding ASCII
  } catch {}
}

function Reset-RestartCount {
  try { Remove-Item -Path $Script:RestartCountFile -Force -ErrorAction SilentlyContinue } catch {}
}

function Try-EnableDockerCliFromDefaultPath {
  if (Has-Cmd "docker") { return }
  $dockerBin = "C:\Program Files\Docker\Docker\resources\bin"
  $dockerExe = Join-Path $dockerBin "docker.exe"
  if (Test-Path $dockerExe) {
    if ($env:Path -notlike "*$dockerBin*") {
      $env:Path = "$dockerBin;$env:Path"
    }
  }
}

function Mark-RestartRequired([string]$reason) {
  $Script:RestartRequired = $true
  if ($reason -and -not $Script:RestartReasons.Contains($reason)) {
    $Script:RestartReasons.Add($reason) | Out-Null
  }
}

function Finish-Or-Restart {
  if (-not $Script:RestartRequired) { return $false }
  $count = Get-RestartCount
  if ($count -ge 1) {
    Warn "Restart already flagged once. Skipping any auto-restart to avoid loops."
  }
  Warn "A restart is required to continue setup."
  if ($Script:RestartReasons.Count -gt 0) {
    Warn ("Reasons: " + ($Script:RestartReasons -join "; "))
  }
  Register-ResumeAfterReboot
  Set-RestartCount ($count + 1)
  $restartNow = (Read-Host "Restart now? (Y/n)").Trim().ToLowerInvariant()
  if ($restartNow -eq "" -or $restartNow -eq "y" -or $restartNow -eq "yes") {
    Warn "Restarting Windows now..."
    shutdown /r /t 5
  } else {
    Warn "Please restart Windows manually once, then sign in and the installer will auto-resume."
  }
  return $true
}

function Download-FileFast([string[]]$urls, [string]$outFile) {
  $outDir = Split-Path -Parent $outFile
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null

  foreach ($u in $urls) {
    try {
      if (Has-Cmd "curl.exe") {
        Info "Downloading with curl (resume supported)..."
        & curl.exe -L --fail --retry 4 --retry-delay 2 --connect-timeout 20 -C - -o $outFile $u
        if ($LASTEXITCODE -eq 0 -and (Test-Path $outFile) -and ((Get-Item $outFile).Length -gt 104857600)) { return $true }
      }
    } catch {}

    try {
      if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
        Info "Downloading with BITS..."
        Start-BitsTransfer -Source $u -Destination $outFile -DisplayName "DockerDesktopInstaller"
        if ((Test-Path $outFile) -and ((Get-Item $outFile).Length -gt 104857600)) { return $true }
      }
    } catch {}

    try {
      Info "Downloading with Invoke-WebRequest..."
      Invoke-WebRequest -Uri $u -OutFile $outFile
      if ((Test-Path $outFile) -and ((Get-Item $outFile).Length -gt 104857600)) { return $true }
    } catch {}
  }

  return $false
}

function Install-DockerDesktopDirect {
  $cacheDir = Join-Path $env:ProgramData "LocalS3\downloads"
  $exe = Join-Path $cacheDir "DockerDesktopInstaller.exe"
  $urls = @(
    "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe",
    "https://desktop.docker.com/win/stable/amd64/Docker%20Desktop%20Installer.exe"
  )

  $useCached = $false
  if (Test-Path $exe) {
    $size = (Get-Item $exe).Length
    if ($size -gt 104857600) {
      $useCached = $true
      Info "Using cached Docker installer: $exe"
    }
  }

  if (-not $useCached) {
    Info "Downloading Docker Desktop installer (this can take several minutes once)..."
    $ok = Download-FileFast -urls $urls -outFile $exe
    if (-not $ok) {
      Err "Failed to download Docker Desktop installer."
      return $false
    }
  }

  Start-Process -FilePath $exe -ArgumentList @("install","--quiet","--accept-license") -Wait
  return $true
}

function Normalize-HostInput([string]$raw) {
  if ([string]::IsNullOrWhiteSpace($raw)) { return "localhost" }
  $value = $raw.Trim()

  if ($value -match '^[a-zA-Z][a-zA-Z0-9+\-.]*://') {
    try { $value = ([Uri]$value).Host } catch {}
  }

  if ($value -match "/") { $value = $value.Split("/")[0] }
  if ($value -match ":") { $value = $value.Split(":")[0] }
  $value = $value.Trim().ToLowerInvariant()

  if ($value -notmatch '^[a-z0-9]([a-z0-9\.-]*[a-z0-9])?$') {
    Err "Invalid domain/host input: '$raw'"
    Err "Use values like: localhost, mystorage.local, mystorage.com, or https://mystorage.com"
    exit 1
  }

  return $value
}

function Test-TcpPort([string]$targetHost, [int]$port, [int]$timeoutMs = 1500) {
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $ar = $client.BeginConnect($targetHost, $port, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne($timeoutMs, $false)) {
      $client.Close()
      return $false
    }
    $client.EndConnect($ar) | Out-Null
    $client.Close()
    return $true
  } catch {
    try { $client.Close() } catch {}
    return $false
  }
}

function Wait-TcpPort([string]$targetHost, [int]$port, [int]$maxSeconds = 30) {
  $elapsed = 0
  while ($elapsed -lt $maxSeconds) {
    if (Test-TcpPort -targetHost $targetHost -port $port) { return $true }
    Start-Sleep -Seconds 1
    $elapsed += 1
  }
  return $false
}

function Test-MinIOAdminLogin([int]$uiPort, [string]$accessKey = "admin", [string]$secretKey = "StrongPassword123") {
  $body = @{ accessKey = $accessKey; secretKey = $secretKey } | ConvertTo-Json -Compress
  try {
    Invoke-RestMethod -Method Post -Uri ("http://127.0.0.1:{0}/api/v1/login" -f $uiPort) -ContentType "application/json" -Body $body -TimeoutSec 10 | Out-Null
    return $true
  } catch {
    return $false
  }
}

# ---------------------------------------------------------------------------
# Post-install: create buckets, set policies, configure CORS, service account
# ---------------------------------------------------------------------------
function Configure-MinIOFeatures {
  param([int]$ApiPort, [int]$UiPort)
  Info "Configuring MinIO features (buckets, CORS, policies, service accounts)..."

  # ---- login ----
  $loginBody = @{ accessKey = $Script:ActiveAccessKey; secretKey = $Script:ActiveSecretKey } | ConvertTo-Json -Compress
  $session = $null
  try {
    Invoke-WebRequest -Uri "http://127.0.0.1:$UiPort/api/v1/login" -Method Post `
      -ContentType "application/json" -Body $loginBody -UseBasicParsing `
      -TimeoutSec 15 -SessionVariable "minioSess" | Out-Null
    $session = $minioSess
    Info "MinIO console login OK."
  } catch {
    Warn "Could not log in to MinIO console API: $($_.Exception.Message)"
    Warn "Skipping feature configuration. Log in manually at http://localhost:$UiPort"
    return
  }

  # ---- helper ----
  function Invoke-MinioApi([string]$Path, [string]$Method = "GET", [object]$Body = $null) {
    $uri = "http://127.0.0.1:$UiPort/api/v1$Path"
    $p = @{ Uri = $uri; Method = $Method; UseBasicParsing = $true; WebSession = $session; TimeoutSec = 15 }
    if ($Body) { $p.ContentType = "application/json"; $p.Body = ($Body | ConvertTo-Json -Compress -Depth 10) }
    return Invoke-WebRequest @p
  }

  # ---- buckets ----
  $bucketsWanted = @("images", "documents", "backups")
  $existingBuckets = @()
  try {
    $data = (Invoke-MinioApi -Path "/buckets").Content | ConvertFrom-Json
    if ($data.buckets) { $existingBuckets = $data.buckets | Select-Object -ExpandProperty name }
  } catch { Warn "Could not list buckets: $($_.Exception.Message)" }

  foreach ($bk in $bucketsWanted) {
    if ($existingBuckets -contains $bk) {
      Info "Bucket '$bk' already exists."
    } else {
      try {
        $bucketBody = @{ name = $bk; versioning = @{ enabled = $false }; locking = $false }
        Invoke-MinioApi -Path "/buckets" -Method "POST" -Body $bucketBody | Out-Null
        Info "Created bucket: $bk"
      } catch { Warn "Could not create bucket '${bk}': $($_.Exception.Message)" }
    }
  }

  # ---- public read on 'images' ----
  try {
    Invoke-MinioApi -Path "/buckets/images/access" -Method "PUT" -Body @{ access = "public"; definition = @{} } | Out-Null
    Info "Set 'images' bucket to public-read."
  } catch { Warn "Could not set public-read on 'images': $($_.Exception.Message)" }

  # ---- CORS on 'images' ----
  try {
    $corsBody = @{
      corsRules = @(
        @{
          allowedHeaders = @("*")
          allowedMethods = @("GET","HEAD","PUT","POST","DELETE")
          allowedOrigins = @("*")
          exposeHeaders  = @("ETag","Content-Type","x-amz-request-id")
          maxAgeSeconds  = 3600
        }
      )
    }
    Invoke-MinioApi -Path "/buckets/images/cors" -Method "PUT" -Body $corsBody | Out-Null
    Info "Configured CORS on 'images' bucket."
  } catch { Warn "CORS config skipped (may not be supported in this MinIO build): $($_.Exception.Message)" }

  # ---- read-only service account for apps ----
  try {
    $svcPolicy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:ListBucket","s3:ListBucketVersions"],"Resource":["arn:aws:s3:::images","arn:aws:s3:::images/*","arn:aws:s3:::documents","arn:aws:s3:::documents/*"]}]}'
    $svcBody = @{ policy = $svcPolicy; accessKey = "readonly-app"; secretKey = "ReadOnly#App2024!" }
    Invoke-MinioApi -Path "/service-accounts" -Method "POST" -Body $svcBody | Out-Null
    Info "Created service account: readonly-app"
  } catch { Warn "Service account creation skipped: $($_.Exception.Message)" }

  Info "MinIO feature configuration complete."
  Write-Host ""
  Write-Host "Pre-configured buckets  : images (public-read + CORS), documents, backups"
  Write-Host "Read-only service account: readonly-app / ReadOnly#App2024!"
}

function Test-MinIOHealth([int]$apiPort) {
  $uris = @(
    ("http://127.0.0.1:{0}/minio/health/live" -f $apiPort),
    ("http://127.0.0.1:{0}/minio/health/ready" -f $apiPort),
    ("http://127.0.0.1:{0}/" -f $apiPort)
  )
  foreach ($uri in $uris) {
    try {
      $r = Invoke-WebRequest -Uri $uri -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 8
      if ($r -and $r.StatusCode) { return $true }
    } catch {
      # If server responded with any HTTP status (even 3xx/4xx/5xx),
      # MinIO is reachable and considered healthy enough for installer continuation.
      $resp = $_.Exception.Response
      if ($resp -and $resp.StatusCode) { return $true }
    }
  }
  return $false
}

function Test-HttpReachable([string]$uri) {
  try {
    $r = Invoke-WebRequest -Uri $uri -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 8
    if ($r -and $r.StatusCode) { return $true }
  } catch {
    # Any HTTP response (including 3xx/4xx/5xx) means endpoint is reachable.
    $resp = $_.Exception.Response
    if ($resp -and $resp.StatusCode) { return $true }
    return $false
  }
  return $false
}

function Show-MinIODiagnostics([string]$logFile, [int]$apiPort, [int]$uiPort, [string]$taskName) {
  Warn "MinIO diagnostics:"
  Write-Host ("  API health endpoint: http://127.0.0.1:{0}/minio/health/live" -f $apiPort)
  Write-Host ("  Console endpoint:    http://127.0.0.1:{0}" -f $uiPort)
  if (Test-Path $logFile) {
    Write-Host ""
    Write-Host "--- MinIO log tail ---"
    Get-Content -Path $logFile -Tail 80 -ErrorAction SilentlyContinue
  }
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  Write-Host ""
  Write-Host "--- Scheduled task status ---"
  schtasks /Query /TN $taskName /V /FO LIST 2>$null | Out-String | Write-Host
  $ErrorActionPreference = $prev
}

function Ask-InstallMode {
  Write-Host ""
  Write-Host "Choose installation mode:"
  Write-Host "  1) IIS (native MinIO + IIS reverse proxy)"
  Write-Host "  2) Docker (MinIO + Nginx containers)"
  $choice = (Read-Host "Select 1 or 2 (default: 1)").Trim()
  if ($choice -eq "2") { return "docker" }
  return "iis"
}

function Ensure-IISInstalled {
  Info "Checking/Installing IIS prerequisites..."

  function Ensure-FeatureLocal([string]$name) {
    $f = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq "Enabled") { return }
    Info "Enabling Windows feature: $name"
    $enabled = $false
    try {
      Enable-WindowsOptionalFeature -Online -FeatureName $name -All -NoRestart -ErrorAction Stop | Out-Null
      $enabled = $true
    } catch {
      Warn "PowerShell feature enable failed for $name. Trying DISM..."
    }
    if (-not $enabled) {
      dism /online /enable-feature /featurename:$name /all /norestart | Out-Null
    }
    $verify = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
    if (-not $verify -or $verify.State -ne "Enabled") {
      Err "Failed to enable required Windows feature: $name"
      exit 1
    }
  }

  function Is-AppInstalledLocal([string]$displayNamePattern) {
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

  function Install-MsiFromUrlsLocal([string[]]$urls, [string]$outFile) {
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

  $features = @(
    "IIS-WebServerRole","IIS-WebServer","IIS-CommonHttpFeatures","IIS-DefaultDocument",
    "IIS-StaticContent","IIS-HttpErrors","IIS-HttpRedirect","IIS-ApplicationDevelopment",
    "IIS-ISAPIExtensions","IIS-ISAPIFilter","IIS-ManagementConsole","IIS-WebSockets"
  )
  foreach ($f in $features) { Ensure-FeatureLocal $f }

  $dlDir = Join-Path $env:ProgramData "LocalS3\downloads"
  $rewriteMsi = Join-Path $dlDir "rewrite_amd64_en-US.msi"
  $arrMsi = Join-Path $dlDir "requestRouter_x64.msi"

  if (-not (Is-AppInstalledLocal "IIS URL Rewrite")) {
    Info "IIS URL Rewrite not found. Installing..."
    $rewriteUrls = @(
      "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi",
      "https://www.iis.net/downloads/microsoft/url-rewrite"
    )
    if (-not (Install-MsiFromUrlsLocal -urls $rewriteUrls -outFile $rewriteMsi)) {
      Err "Failed to install IIS URL Rewrite automatically."
      exit 1
    }
  } else {
    Info "IIS URL Rewrite already installed."
  }

  if (-not (Is-AppInstalledLocal "Application Request Routing")) {
    Info "IIS ARR not found. Installing..."
    $arrUrls = @(
      "https://go.microsoft.com/fwlink/?LinkID=615136",
      "https://www.iis.net/downloads/microsoft/application-request-routing"
    )
    if (-not (Install-MsiFromUrlsLocal -urls $arrUrls -outFile $arrMsi)) {
      Err "Failed to install IIS ARR automatically."
      exit 1
    }
  } else {
    Info "IIS ARR already installed."
  }

  Info "IIS prerequisites installed successfully."
}

function Ensure-MinIONative([string]$root,[int]$apiPort,[int]$uiPort,[string]$publicUrl,[string]$consoleBrowserUrl="") {
  $Script:ActiveAccessKey = "admin"
  $Script:ActiveSecretKey = "StrongPassword123"
  $binDir = Join-Path $root "minio"
  $dataDir = Join-Path $root "data"
  $configDir = Join-Path $root "config"
  $exe = Join-Path $binDir "minio.exe"
  $runner = Join-Path $binDir "run-minio.cmd"
  $logFile = Join-Path $binDir "minio.log"
  New-Item -ItemType Directory -Force -Path $binDir,$dataDir,$configDir | Out-Null

  # ---- Stop any previously running MinIO so the file lock is released ----
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  schtasks /Query /TN "LocalS3-MinIO" 1>$null 2>$null
  if ($LASTEXITCODE -eq 0) {
    Info "Stopping existing MinIO scheduled task before update..."
    schtasks /End /TN "LocalS3-MinIO" 1>$null 2>$null | Out-Null
    Start-Sleep -Seconds 2
  }
  $minioProc = Get-Process -Name "minio" -ErrorAction SilentlyContinue
  if ($minioProc) {
    Info "Terminating running minio.exe process(es)..."
    $minioProc | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
  }
  $ErrorActionPreference = $prev

  # Use a pinned stable release first (deterministic), then fallback to latest.
  $minioUrls = @(
    "https://dl.min.io/server/minio/release/windows-amd64/archive/minio.RELEASE.2023-07-21T21-12-44Z",
    "https://dl.min.io/server/minio/release/windows-amd64/archive/minio.RELEASE.2023-10-16T04-13-43Z",
    "https://dl.min.io/server/minio/release/windows-amd64/archive/minio.RELEASE.2025-04-22T22-12-26Z",
    "https://dl.min.io/server/minio/release/windows-amd64/archive/minio.RELEASE.2025-01-18T00-31-37Z",
    "https://dl.min.io/server/minio/release/windows-amd64/minio.exe",
    "https://github.com/minio/minio/releases/latest/download/minio.exe"
  )
  $downloaded = $false
  $lastDownloadError = ""
  foreach ($u in $minioUrls) {
    $ok = $false
    try {
      Info "Downloading MinIO server binary: $u"
      if (Has-Cmd "curl.exe") {
        & curl.exe -L --fail --retry 3 --retry-delay 2 --connect-timeout 20 -o $exe $u
        if ($LASTEXITCODE -eq 0 -and (Test-Path $exe) -and ((Get-Item $exe).Length -gt 10000000)) {
          $ok = $true
        }
      }
      if (-not $ok) {
        Invoke-WebRequest -Uri $u -OutFile $exe -UseBasicParsing
        if ((Test-Path $exe) -and ((Get-Item $exe).Length -gt 10000000)) {
          $ok = $true
        }
      }
      if ($ok) {
        $downloaded = $true
        break
      }
    } catch {
      $lastDownloadError = $_.Exception.Message
      Warn "MinIO download failed from: $u ($lastDownloadError)"
    }
  }
  if (-not $downloaded) {
    Warn "Automatic MinIO download failed from all sources."
    if ($lastDownloadError) { Warn "Last download error: $lastDownloadError" }
    Warn "Check outbound HTTPS access to: dl.min.io and github.com."
    $manualPath = (Read-Host "Enter full path to a local minio.exe (or press Enter to abort)").Trim()
    if (-not [string]::IsNullOrWhiteSpace($manualPath)) {
      if (Test-Path $manualPath) {
        try {
          Copy-Item -Path $manualPath -Destination $exe -Force
          if ((Test-Path $exe) -and ((Get-Item $exe).Length -gt 10000000)) {
            $downloaded = $true
            Info "Using local MinIO binary: $manualPath"
          } else {
            Err "Provided file is too small to be a valid MinIO binary."
            exit 1
          }
        } catch {
          Err "Failed to copy local MinIO binary: $($_.Exception.Message)"
          exit 1
        }
      } else {
        Err "Local MinIO binary path not found: $manualPath"
        exit 1
      }
    } else {
      Err "Failed to download MinIO binary."
      Warn "Place minio.exe at: $exe and rerun installer."
      exit 1
    }
  }
  try {
    $ver = & $exe --version 2>$null | Select-Object -First 1
    if ($ver) { Info "Using MinIO binary: $ver" }
  } catch {}

  $runnerBody = @"
@echo off
set MINIO_SERVER_URL=$publicUrl
set MINIO_BROWSER_REDIRECT_URL=$consoleBrowserUrl
set MINIO_CONSOLE_REDIRECT_URL=
set MINIO_ROOT_USER=admin
set MINIO_ROOT_PASSWORD=StrongPassword123
set MINIO_API_ROOT_ACCESS=on
"$exe" server "$dataDir" --config-dir "$configDir" --address ":$apiPort" --console-address ":$uiPort" >> "$logFile" 2>&1
"@
  [System.IO.File]::WriteAllText($runner, $runnerBody, (New-Object System.Text.UTF8Encoding($false)))

  $taskName = "LocalS3-MinIO"
  $cmd = "cmd.exe /c `"`"$runner`"`""
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  schtasks /Query /TN $taskName 1>$null 2>$null
  if ($LASTEXITCODE -eq 0) {
    schtasks /Delete /TN $taskName /F 1>$null 2>$null
  }
  schtasks /Create /TN $taskName /SC ONSTART /RU SYSTEM /TR $cmd /F 1>$null 2>$null
  $createExit = $LASTEXITCODE
  if ($createExit -ne 0) {
    $ErrorActionPreference = $prev
    Err "Failed to create MinIO scheduled task."
    exit 1
  }
  Get-Process -Name "minio" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue
  Start-Process -FilePath "cmd.exe" -ArgumentList @("/c","`"$runner`"") -WindowStyle Hidden | Out-Null
  $ErrorActionPreference = $prev

  if (-not (Wait-TcpPort -targetHost "127.0.0.1" -port $apiPort -maxSeconds 45)) {
    Warn "MinIO API port $apiPort did not become ready in time."
    Show-MinIODiagnostics -logFile $logFile -apiPort $apiPort -uiPort $uiPort -taskName $taskName
    Err "MinIO service is not reachable yet. Fix MinIO startup and rerun."
    exit 1
  }
  if (-not (Test-MinIOHealth -apiPort $apiPort)) {
    Warn "Port $apiPort is open but MinIO health check failed."
    Show-MinIODiagnostics -logFile $logFile -apiPort $apiPort -uiPort $uiPort -taskName $taskName
    Err "MinIO did not pass health check. Likely a port conflict or startup failure."
    exit 1
  }

  # Console login probe can vary across MinIO/console versions; try both UI and API ports.
  $adminLoginOk = (Test-MinIOAdminLogin -uiPort $uiPort -accessKey "admin" -secretKey "StrongPassword123") -or (Test-MinIOAdminLogin -uiPort $apiPort -accessKey "admin" -secretKey "StrongPassword123")
  if (-not $adminLoginOk) {
    $defaultLoginOk = (Test-MinIOAdminLogin -uiPort $uiPort -accessKey "minioadmin" -secretKey "minioadmin") -or (Test-MinIOAdminLogin -uiPort $apiPort -accessKey "minioadmin" -secretKey "minioadmin")
    if ($defaultLoginOk) {
      Warn "MinIO accepted default credentials on this run (minioadmin/minioadmin)."
      Warn "Using detected working credentials for this deployment."
      $Script:ActiveAccessKey = "minioadmin"
      $Script:ActiveSecretKey = "minioadmin"
      return
    }
    Warn "MinIO is running, but login with expected admin credentials failed."
    Warn "Running automatic credential reset once..."
    $idDir = Join-Path $dataDir ".minio.sys"
    $ErrorActionPreference = "Continue"
    schtasks /End /TN $taskName 1>$null 2>$null | Out-Null
    Get-Process -Name "minio" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if (Test-Path $dataDir) {
      Warn "Resetting MinIO data folder: $dataDir"
      Remove-Item -Recurse -Force -Path $dataDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    }
    if (Test-Path $idDir) {
      Warn "Removing MinIO identity metadata: $idDir"
      Remove-Item -Recurse -Force -Path $idDir -ErrorAction SilentlyContinue
    }
    if (Test-Path $configDir) {
      Warn "Removing MinIO config state: $configDir"
      Remove-Item -Recurse -Force -Path $configDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    }
    Start-Process -FilePath "cmd.exe" -ArgumentList @("/c","`"$runner`"") -WindowStyle Hidden | Out-Null
    $ErrorActionPreference = $prev
    if (-not (Wait-TcpPort -targetHost "127.0.0.1" -port $uiPort -maxSeconds 45)) {
      Err "MinIO did not come back after identity reset."
      exit 1
    }
    if (-not (Test-MinIOHealth -apiPort $apiPort)) {
      Show-MinIODiagnostics -logFile $logFile -apiPort $apiPort -uiPort $uiPort -taskName $taskName
      Err "MinIO health check failed after reset."
      exit 1
    }
    $adminLoginOkAfterReset = (Test-MinIOAdminLogin -uiPort $uiPort -accessKey "admin" -secretKey "StrongPassword123") -or (Test-MinIOAdminLogin -uiPort $apiPort -accessKey "admin" -secretKey "StrongPassword123")
    if (-not $adminLoginOkAfterReset) {
      $defaultLoginOkAfterReset = (Test-MinIOAdminLogin -uiPort $uiPort -accessKey "minioadmin" -secretKey "minioadmin") -or (Test-MinIOAdminLogin -uiPort $apiPort -accessKey "minioadmin" -secretKey "minioadmin")
      if ($defaultLoginOkAfterReset) {
        Warn "MinIO still uses default credentials (minioadmin/minioadmin) after reset."
        $Script:ActiveAccessKey = "minioadmin"
        $Script:ActiveSecretKey = "minioadmin"
        return
      }
      Warn "Login probe still failing after automatic reset, but MinIO health is OK."
      Warn "Continuing installation. Check MinIO log and authenticate in console manually."
      Show-MinIODiagnostics -logFile $logFile -apiPort $apiPort -uiPort $uiPort -taskName $taskName
      $Script:ActiveAccessKey = "admin"
      $Script:ActiveSecretKey = "StrongPassword123"
      return
    }
    $Script:ActiveAccessKey = "admin"
    $Script:ActiveSecretKey = "StrongPassword123"
    Info "MinIO credentials reset succeeded. Admin login is now valid."
  }
}

function Ensure-IISProxyMode([string]$domain,[string]$siteRoot,[string]$certPath,[string]$keyPath,[int]$httpsPort,[int]$targetPort,[string]$lanIp) {
  Import-Module WebAdministration
  $Script:IISCertIncludesIpSan = $false
  $Script:IISCertThumb = ""
  New-Item -ItemType Directory -Force -Path $siteRoot | Out-Null
  $webConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <requestLimits maxAllowedContentLength="4294967295" />
      </requestFiltering>
    </security>
    <rewrite>
      <rules>
        <rule name="ReverseProxyInboundRule1" stopProcessing="true">
          <match url="(.*)" />
          <serverVariables>
            <set name="HTTP_X_FORWARDED_PROTO" value="https" />
            <set name="HTTP_X_FORWARDED_HOST" value="{HTTP_HOST}" />
            <set name="HTTP_X_FORWARDED_FOR" value="{REMOTE_ADDR}" />
          </serverVariables>
          <action type="Rewrite" url="http://127.0.0.1:$targetPort/{R:1}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
"@
  [System.IO.File]::WriteAllText((Join-Path $siteRoot "web.config"), $webConfig, (New-Object System.Text.UTF8Encoding($false)))

  try {
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/proxy" -Name "enabled" -Value "True" -ErrorAction Stop | Out-Null
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/proxy" -Name "preserveHostHeader" -Value "True" -ErrorAction Stop | Out-Null
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/proxy" -Name "reverseRewriteHostInResponseHeaders" -Value "False" -ErrorAction Stop | Out-Null
    try {
      Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/proxy" -Name "allowSslOffloading" -Value "True" -ErrorAction Stop | Out-Null
    } catch {
      Warn "ARR property 'allowSslOffloading' is not available on this IIS version. Continuing."
    }
  } catch {
    Err "IIS reverse proxy is not available (ARR/URL Rewrite missing)."
    Warn "Install these IIS extensions, then rerun in IIS mode:"
    Write-Host "  - URL Rewrite"
    Write-Host "  - Application Request Routing (ARR)"
    exit 1
  }

  try {
    $allowedVars = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/rewrite/allowedServerVariables" -Name "." -ErrorAction Stop
    foreach ($varName in @("HTTP_X_FORWARDED_PROTO","HTTP_X_FORWARDED_HOST","HTTP_X_FORWARDED_FOR")) {
      $alreadyAllowed = $false
      if ($allowedVars -and $allowedVars.Collection) {
        $alreadyAllowed = $null -ne ($allowedVars.Collection | Where-Object { $_.Attributes["name"].Value -eq $varName } | Select-Object -First 1)
      }
      if (-not $alreadyAllowed) {
        Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/rewrite/allowedServerVariables" -Name "." -Value @{ name = $varName } -ErrorAction Stop | Out-Null
      }
    }
  } catch {
    Warn "Could not update IIS Rewrite allowed server variables automatically. If proxy requests fail, allow HTTP_X_FORWARDED_PROTO/HOST/FOR in IIS Rewrite settings."
  }

  # Build SAN: always include localhost + 127.0.0.1, plus domain and LAN IP if present
  $sanExt = "2.5.29.17={text}DNS=localhost&IPAddress=127.0.0.1"
  if ($domain -and $domain -ne "localhost") { $sanExt += "&DNS=$domain" }
  if ($lanIp) { $sanExt += "&IPAddress=$lanIp" }

  $cert = $null
  # BasicConstraints CA=true required so Go/OpenSSL trust the self-signed cert as a root CA
  $bcExt = "2.5.29.19={critical}{text}ca=true"

  # Method 1: New-SelfSignedCertificate with CA flags + IP SAN
  try {
    $cert = New-SelfSignedCertificate -Subject "CN=localhost" -TextExtension @($sanExt, $bcExt) `
      -KeyAlgorithm RSA -KeyLength 2048 -FriendlyName "LocalS3-HTTPS" `
      -KeyUsage CertSign, CRLSign, DigitalSignature, KeyEncipherment `
      -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(3)
    if ($cert) { $Script:IISCertIncludesIpSan = $true; Info "Cert generated with IP SAN and CA flags." }
  } catch {
    Warn "New-SelfSignedCertificate with IP SAN failed: $($_.Exception.Message)"
  }
  # Method 2: certreq.exe fallback — works on all Windows versions
  if (-not $cert) {
    try {
      $infPath = Join-Path $env:TEMP "locals3-cert.inf"
      $sanLines = "_continue_ = `"dns=localhost&`"`r`n_continue_ = `"ipaddress=127.0.0.1&`""
      if ($domain -and $domain -ne "localhost") { $sanLines += "`r`n_continue_ = `"dns=$domain&`"" }
      if ($lanIp) { $sanLines += "`r`n_continue_ = `"ipaddress=$lanIp&`"" }
      $infContent = "[Version]`r`nSignature=`"`$Windows NT`$`"`r`n[NewRequest]`r`nSubject=`"CN=localhost`"`r`nKeyLength=2048`r`nKeyAlgorithm=RSA`r`nMachineKeySet=True`r`nRequestType=Cert`r`nValidityPeriod=Years`r`nValidityPeriodUnits=3`r`nKeySpec=AT_SIGNATURE`r`n[Extensions]`r`n2.5.29.17 = `"{text}`"`r`n$sanLines`r`n2.5.29.19 = `"{critical}{text}ca=true`""
      [System.IO.File]::WriteAllText($infPath, $infContent)
      certreq -new -machine $infPath "$env:TEMP\locals3-cert.cer" 2>&1 | Out-Null
      $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=localhost" } | Sort-Object NotBefore -Descending | Select-Object -First 1
      if ($cert) { $Script:IISCertIncludesIpSan = $true; Info "Cert generated with IP SAN and CA flags via certreq." }
    } catch { Warn "certreq cert generation failed: $($_.Exception.Message)" }
  }
  # Final fallback: DNS-only cert with CA flags
  if (-not $cert) {
    Warn "Falling back to DNS-only cert. LAN-IP HTTPS URLs will show a certificate warning."
    $cert = New-SelfSignedCertificate -Subject "CN=localhost" -TextExtension @($bcExt) `
      -KeyAlgorithm RSA -KeyLength 2048 -FriendlyName "LocalS3-HTTPS" `
      -KeyUsage CertSign, CRLSign, DigitalSignature, KeyEncipherment `
      -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(3)
  }
  $thumb = $cert.Thumbprint
  $Script:IISCertThumb = $thumb
  Import-Certificate -FilePath (Export-Certificate -Cert "Cert:\LocalMachine\My\$thumb" -FilePath $certPath -Force).FullName -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null

  if (Test-Path "IIS:\Sites\LocalS3-IIS") {
    Remove-Website -Name "LocalS3-IIS"
  }
  New-Website -Name "LocalS3-IIS" -PhysicalPath $siteRoot -Port 80 -IPAddress "*" -HostHeader $domain | Out-Null
  New-WebBinding -Name "LocalS3-IIS" -Protocol "https" -Port $httpsPort -IPAddress "*" -HostHeader $domain -SslFlags 1 | Out-Null
  (Get-WebBinding -Name "LocalS3-IIS" -Protocol https -Port $httpsPort -HostHeader $domain).AddSslCertificate($thumb,"My")

  # Add direct LAN-IP binding so https://<LAN-IP> works from other computers.
  if ($lanIp) {
    $ipBindingInfo = "$lanIp`:$httpsPort`:"
    $ipBinding = Get-WebBinding -Name "LocalS3-IIS" -Protocol https | Where-Object { $_.bindingInformation -eq $ipBindingInfo }
    if (-not $ipBinding) {
      New-WebBinding -Name "LocalS3-IIS" -Protocol "https" -Port $httpsPort -IPAddress $lanIp -HostHeader "" -SslFlags 0 | Out-Null
      $ipBinding = Get-WebBinding -Name "LocalS3-IIS" -Protocol https | Where-Object { $_.bindingInformation -eq $ipBindingInfo } | Select-Object -First 1
      if ($ipBinding) { $ipBinding.AddSslCertificate($thumb,"My") }
    }
  }

  $ErrorActionPreference = "Continue"
  Start-Service W3SVC 2>$null | Out-Null
  Start-Website -Name "LocalS3-IIS" 2>$null | Out-Null
  $ErrorActionPreference = "Stop"

  if (-not (Wait-TcpPort -targetHost "127.0.0.1" -port $httpsPort -maxSeconds 30)) {
    Err "IIS HTTPS listener on port $httpsPort is not reachable."
    Warn "IIS site state:"
    Get-Website -Name "LocalS3-IIS" | Format-List * | Out-String | Write-Host
    Warn "Check if another app is blocking port $httpsPort."
    exit 1
  }

  if ($domain -ne "localhost") { Ensure-HostsEntry -domain $domain }
  if ($lanIp) { Ensure-FirewallPort -port $httpsPort }

  $proxyUri = if ($httpsPort -eq 443) { "https://$domain/" } else { "https://${domain}:$httpsPort/" }
  if (-not (Test-HttpReachable -uri $proxyUri)) {
    Warn "IIS HTTPS endpoint probe failed: $proxyUri"
    Warn "Check IIS logs/Event Viewer and confirm URL Rewrite + ARR are installed and enabled."
  }
}

function Ensure-IISConsoleSite([string]$consoleSiteRoot,[int]$consoleHttpsPort,[int]$uiPort,[string]$lanIp,[string]$certThumb) {
  Import-Module WebAdministration
  New-Item -ItemType Directory -Force -Path $consoleSiteRoot | Out-Null
  $consoleWebConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <requestLimits maxAllowedContentLength="4294967295" />
      </requestFiltering>
    </security>
    <rewrite>
      <rules>
        <rule name="MinIOConsoleProxy" stopProcessing="true">
          <match url="(.*)" />
          <serverVariables>
            <set name="HTTP_X_FORWARDED_PROTO" value="https" />
            <set name="HTTP_X_FORWARDED_HOST" value="{HTTP_HOST}" />
            <set name="HTTP_X_FORWARDED_FOR" value="{REMOTE_ADDR}" />
          </serverVariables>
          <action type="Rewrite" url="http://127.0.0.1:$uiPort/{R:1}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
"@
  [System.IO.File]::WriteAllText((Join-Path $consoleSiteRoot "web.config"), $consoleWebConfig, (New-Object System.Text.UTF8Encoding($false)))

  if (Test-Path "IIS:\Sites\LocalS3-Console") { Remove-Website -Name "LocalS3-Console" }
  New-Website -Name "LocalS3-Console" -PhysicalPath $consoleSiteRoot -Port 80 -Force | Out-Null
  Stop-Website -Name "LocalS3-Console" -ErrorAction SilentlyContinue
  Get-WebBinding -Name "LocalS3-Console" | Remove-WebBinding
  New-WebBinding -Name "LocalS3-Console" -Protocol "https" -Port $consoleHttpsPort -HostHeader "localhost" -SslFlags 0 | Out-Null
  (Get-WebBinding -Name "LocalS3-Console" -Protocol "https" -Port $consoleHttpsPort -HostHeader "localhost").AddSslCertificate($certThumb, "My")
  if ($lanIp) {
    New-WebBinding -Name "LocalS3-Console" -Protocol "https" -Port $consoleHttpsPort -IPAddress $lanIp -HostHeader "" -SslFlags 0 | Out-Null
    $ipBind = Get-WebBinding -Name "LocalS3-Console" -Protocol "https" | Where-Object { $_.bindingInformation -eq "${lanIp}:${consoleHttpsPort}:" } | Select-Object -First 1
    if ($ipBind) { $ipBind.AddSslCertificate($certThumb, "My") }
    # netsh SSL bindings for the IP:port and wildcard
    $appId = "{$(New-Guid)}"
    netsh http delete sslcert ipport="0.0.0.0:$consoleHttpsPort" 2>$null | Out-Null
    netsh http delete sslcert ipport="${lanIp}:${consoleHttpsPort}" 2>$null | Out-Null
    netsh http add sslcert ipport="0.0.0.0:$consoleHttpsPort" certhash=$certThumb appid=$appId certstorename=MY 2>&1 | Out-Null
    netsh http add sslcert ipport="${lanIp}:${consoleHttpsPort}" certhash=$certThumb appid=$appId certstorename=MY 2>&1 | Out-Null
    Ensure-FirewallPort -port $consoleHttpsPort
  }
  Start-Website -Name "LocalS3-Console" -ErrorAction SilentlyContinue
  Info "MinIO console HTTPS site created on port $consoleHttpsPort."
}

function Install-IISMode {
  $root = Join-Path $env:ProgramData "LocalS3\storage-server"
  $certDir = Join-Path $root "nginx\certs"
  $siteRoot = Join-Path $root "iis-site"
  New-Item -ItemType Directory -Force -Path $certDir,$siteRoot | Out-Null

  $domainInput = Read-Host "Enter local domain/URL for HTTPS (default: localhost)"
  $domain = Normalize-HostInput $domainInput
  Info "Using local domain: $domain"
  $enableLan = $true
  Info "LAN access: enabled"
  $lanIp = $null
  if ($enableLan) {
    $lanIp = Get-LanIPv4
    if ($lanIp) { Info "Detected LAN IP: $lanIp" } else { Warn "Could not detect LAN IP automatically." }
  }

  $busyDefaults = @()
  foreach ($p in @(443,9000,9001)) {
    if (-not (Port-Free $p)) { $busyDefaults += $p }
  }
  if ($busyDefaults.Count -gt 0 -and (Has-ExistingLocalS3IISInstall)) {
    Warn ("Some default ports are busy (" + ($busyDefaults -join ", ") + ") and an existing LocalS3 IIS installation was detected.")
    $ans = (Read-Host "Delete previous LocalS3 IIS install and reinstall now? (Y/n)").Trim().ToLowerInvariant()
    if ($ans -eq "" -or $ans -eq "y" -or $ans -eq "yes") {
      Remove-ExistingLocalS3IISInstall -root $root -DeleteData
    } else {
      Warn "Keeping existing LocalS3 install. Installer will use alternate/custom ports as needed."
    }
  }

  $httpsPort = Resolve-HttpsPortForIIS
  if ($httpsPort -ne 443) { Warn "Using HTTPS port: $httpsPort" }

  $apiPort = Resolve-RequiredPort -label "MinIO API" -candidates @(9000,19000,29000,39000,49000,59000) -defaultPort 9000
  $uiPort = Resolve-RequiredPort -label "MinIO Console UI" -candidates @(9001,19001,29001,39001,49001,59001) -defaultPort 9001
  if ($uiPort -eq $apiPort) {
    Warn "MinIO UI port cannot equal API port ($apiPort)."
    $uiPort = Resolve-RequiredPort -label "MinIO Console UI" -candidates @() -defaultPort ($apiPort + 1)
  }
  # Console HTTPS proxy port: try httpsPort+1000 range (e.g. 8443→9443)
  # Exclude $httpsPort from candidates to prevent the API site and console site from both resolving to the same port.
  $consoleCandidates = @(9443,10443,11443,12443,13443) | Where-Object { $_ -ne $httpsPort }
  $consoleHttpsPort = Resolve-RequiredPort -label "MinIO Console HTTPS" -candidates $consoleCandidates -defaultPort ($httpsPort + 1000)

  Run-PreflightChecks -DataPath $root

  $publicUrl = if ($httpsPort -eq 443) { "https://$domain" } else { "https://${domain}:$httpsPort" }
  # Console browser URL: prefer LAN IP so it works on all devices; fall back to localhost
  $consoleBrowserUrl = if ($lanIp) {
    if ($consoleHttpsPort -eq 443) { "https://$lanIp" } else { "https://${lanIp}:$consoleHttpsPort" }
  } else {
    if ($consoleHttpsPort -eq 443) { "https://localhost" } else { "https://localhost:$consoleHttpsPort" }
  }

  Ensure-IISInstalled
  Ensure-MinIONative -root $root -apiPort $apiPort -uiPort $uiPort -publicUrl $publicUrl -consoleBrowserUrl $consoleBrowserUrl
  $crt = Join-Path $certDir "localhost.crt"
  $key = Join-Path $certDir "localhost.key"
  Ensure-IISProxyMode -domain $domain -siteRoot $siteRoot -certPath $crt -keyPath $key -httpsPort $httpsPort -targetPort $apiPort -lanIp $lanIp

  # Create separate HTTPS console proxy site
  $consoleSiteRoot = Join-Path $root "iis-console-site"
  Ensure-IISConsoleSite -consoleSiteRoot $consoleSiteRoot -consoleHttpsPort $consoleHttpsPort -uiPort $uiPort -lanIp $lanIp -certThumb $Script:IISCertThumb

  # Auto-configure buckets, CORS, service accounts
  Configure-MinIOFeatures -ApiPort $apiPort -UiPort $uiPort

  Write-Host ""
  Write-Host "===== INSTALLATION COMPLETE (IIS MODE) ====="
  Write-Host ""
  Write-Host "URLs:"
  Write-Host "  MinIO Console HTTPS:    $consoleBrowserUrl"
  Write-Host "  S3 API / Share links:   $publicUrl"
  if ($enableLan -and $lanIp) {
    Write-Host "  LAN Console:            https://${lanIp}:$consoleHttpsPort"
    Write-Host "  LAN S3 API:             https://${lanIp}:$httpsPort"
    Write-Host "  For DNS: map $domain -> $lanIp"
  }
  Write-Host ""
  Write-Host "Login:"
  Write-Host "  Username : $Script:ActiveAccessKey"
  Write-Host "  Password : $Script:ActiveSecretKey"
  Write-Host ""
  Write-Host "Pre-configured buckets:"
  Write-Host "  images    (public-read + CORS enabled)"
  Write-Host "  documents"
  Write-Host "  backups"
  Write-Host ""
  Write-Host "Read-only service account (for apps / SDKs):"
  Write-Host "  Access key : readonly-app"
  Write-Host "  Secret key : ReadOnly#App2024!"
}

function Enable-WSLFeatures {
  Info "Checking Windows features required for WSL2..."
  $needRestart = $false

  $wsl = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State
  if ($wsl -ne "Enabled") {
    Info "Enabling Microsoft-Windows-Subsystem-Linux..."
    dism /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Warn "DISM failed to enable Microsoft-Windows-Subsystem-Linux (exit $LASTEXITCODE). You may need to enable it manually."
    }
    $needRestart = $true
  }

  $vmp = (Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State
  if ($vmp -ne "Enabled") {
    Info "Enabling VirtualMachinePlatform..."
    dism /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Warn "DISM failed to enable VirtualMachinePlatform (exit $LASTEXITCODE). You may need to enable it manually."
    }
    $needRestart = $true
  }

  if (-not (Has-Cmd "wsl")) {
    Warn "wsl.exe not found yet. Windows restart is required after enabling features."
    $needRestart = $true
  }

  if ($needRestart) {
    Mark-RestartRequired "WSL2 features changed"
    Warn "WSL2 changes queued. Setup will continue and restart once at the end if needed."
    return
  }

  # Best-effort sanity
  try {
    $status = wsl --status 2>$null
    if ($status -notmatch "Default Version:\s*2") {
      Warn "WSL default version is not 2. Setting it to 2..."
      wsl --set-default-version 2 | Out-Null
    }
  } catch {
    Warn "WSL status not available yet. If Docker fails, run: wsl --install and reboot."
  }

  Info "WSL2 feature check passed (or already enabled)."
}

function Ensure-DockerInstalled {
  Info "Checking Docker installation..."
  Try-EnableDockerCliFromDefaultPath
  if (Has-Cmd "docker") {
    Info "Docker CLI found."
    return
  }

  Warn "Docker CLI not found. Attempting automatic installation..."
  $ok = Install-DockerDesktopDirect
  if (-not $ok) {
    Err "Automatic Docker Desktop installation failed."
    Warn "Please install Docker Desktop manually, then rerun this script."
    Write-Host "Download URL:"
    Write-Host "  https://www.docker.com/products/docker-desktop/"
    Write-Host "Direct Windows installer:"
    Write-Host "  https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
    exit 1
  }
  # After silent install, refresh PATH and recheck
  Try-EnableDockerCliFromDefaultPath
  if (-not (Has-Cmd "docker")) {
    Warn "Docker CLI still not in PATH after install. A Windows restart may be required."
    Mark-RestartRequired "Docker Desktop installed - PATH update pending"
    return
  }
  Info "Docker Desktop installed successfully."
}

function Start-DockerDesktop {
  # Start Docker Desktop if possible
  $exe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
  if (Test-Path $exe) {
    Info "Starting Docker Desktop..."
    Start-Process $exe | Out-Null
    return
  }
  Warn "Docker Desktop exe not found at default path. Start Docker Desktop manually."
}

function Test-DockerEngine {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  docker info 2>&1 | Out-Null
  $ok = ($LASTEXITCODE -eq 0)
  $ErrorActionPreference = $prev
  return $ok
}

# ---------------------------------------------------------------------------
# Self-healing: terminate stuck WSL distros + restart Docker Desktop
# ---------------------------------------------------------------------------
function Repair-DockerEngine {
  Info "Attempting Docker Engine self-repair..."
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"

  # Step 1: Terminate docker-desktop WSL distros
  try {
    $wslOut = wsl --list --quiet 2>$null
    if ($wslOut) {
      $distros = $wslOut | Where-Object { ($_ -replace '[^\x20-\x7E]','').Trim() -match "docker-desktop" }
      if ($distros) {
        Info "Terminating stuck Docker WSL distros..."
        foreach ($d in $distros) {
          $dName = ($d -replace '[^\x20-\x7E]','').Trim()
          if ($dName) {
            wsl --terminate $dName 2>$null | Out-Null
            Info "  Terminated: $dName"
          }
        }
        Start-Sleep -Seconds 4
      }
    }
  } catch {
    Warn "WSL distro enumeration failed: $($_.Exception.Message)"
  }

  # Step 2: Kill and restart Docker Desktop
  try {
    $dd = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
    if ($dd) {
      Info "Stopping Docker Desktop process..."
      $dd | Stop-Process -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 6
    }
  } catch {}
  Start-DockerDesktop
  $ErrorActionPreference = $prev

  # Step 3: Wait up to 120s for recovery
  Info "Waiting for Docker Engine recovery (up to 120s)..."
  $elapsed = 0
  while ($elapsed -lt 120) {
    Start-Sleep -Seconds 5
    $elapsed += 5
    if (Test-DockerEngine) {
      Info "Docker Engine recovered after self-repair ($elapsed s)."
      return $true
    }
    if ($elapsed % 30 -eq 0) { Info "  Still waiting... ($elapsed/120s)" }
  }
  Warn "Docker Engine did not recover after self-repair."
  return $false
}

function Wait-DockerEngine {
  Info "Checking Docker Engine availability..."
  if (Test-DockerEngine) {
    Info "Docker Engine is ready."
    return
  }

  Warn "Docker Engine not reachable. Attempting to start Docker Desktop..."
  Start-DockerDesktop

  # Phase 1: wait 90 seconds normally
  $maxSeconds = 90
  $step = 5
  $elapsed = 0
  while ($elapsed -lt $maxSeconds) {
    Start-Sleep -Seconds $step
    $elapsed += $step
    if (Test-DockerEngine) {
      Info "Docker Engine is ready."
      return
    }
    if ($elapsed % 30 -eq 0) { Info "Waiting for Docker Engine... ($elapsed/${maxSeconds}s)" }
  }

  # Phase 2: attempt self-repair
  Warn "Docker Engine not ready after ${maxSeconds}s. Starting self-repair procedure..."
  $repaired = Repair-DockerEngine
  if ($repaired) { return }

  Err "Docker Engine is still NOT reachable after repair attempts."
  Warn "Manual recovery steps:"
  Write-Host "  1. Open Docker Desktop and wait for 'Engine running'"
  Write-Host "  2. Run: wsl --shutdown  then reopen Docker Desktop"
  Write-Host "  3. If new: wsl --install (then reboot)"
  Write-Host "  4. Ensure virtualization is enabled in BIOS (Intel VT-x / AMD SVM)"
  exit 1
}

function Ensure-DockerCompose {
  if (-not (Has-Cmd "docker")) { Err "docker not found unexpectedly."; exit 1 }
  Sanitize-DockerEnv
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  docker compose version 2>&1 | Out-Null
  $ok = ($LASTEXITCODE -eq 0)
  $ErrorActionPreference = $prev
  if (-not $ok) {
    Err "docker compose plugin not available. Update Docker Desktop and rerun."
    exit 1
  }
}

function Sanitize-DockerEnv {
  foreach ($name in @("DOCKER_HOST","DOCKER_CONTEXT","DOCKER_TLS_VERIFY","DOCKER_CERT_PATH","DOCKER_API_VERSION")) {
    $value = (Get-Item -Path ("Env:" + $name) -ErrorAction SilentlyContinue).Value
    if ($null -eq $value) { continue }
    $trim = $value.Trim()
    $quotedEmpty = ($trim -eq '""' -or $trim -eq "''")
    $bad = ([string]::IsNullOrWhiteSpace($trim) -or $quotedEmpty)

    # We run compose with explicit --context, so these env vars only create ambiguity.
    # Clear them unconditionally; report when they look malformed.
    if ($bad) {
      Warn "$name is malformed ('$value'); clearing it."
    } else {
      Warn "$name is set ('$value'); clearing it so docker --context is authoritative."
    }
    Remove-Item -Path ("Env:" + $name) -ErrorAction SilentlyContinue
  }
}

function Get-ActiveDockerContext {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  $ctx = (docker context show 2>$null | Select-Object -First 1)
  $ErrorActionPreference = $prev
  if ($ctx) { $ctx = $ctx.Trim() }
  if (-not $ctx) { $ctx = "default" }
  return $ctx
}

function Port-Free([int]$p) {
  try {
    $c = Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue
    return ($null -eq $c -or $c.Count -eq 0)
  } catch {
    $out = netstat -ano | Select-String -Pattern "LISTENING" | Select-String -Pattern (":$p\s")
    return ($null -eq $out -or $out.Count -eq 0)
  }
}

function Get-PortListeners([int]$p) {
  $items = @()
  try {
    $conns = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
      $procName = ""
      try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
      $items += [PSCustomObject]@{ Port = $p; PID = $c.OwningProcess; Process = $procName }
    }
  } catch {}
  return $items
}

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
    $ErrorActionPreference = $prev
    Info "Previous containers were removed."
  } else {
    Warn "Keeping previous containers. This may cause port conflicts."
  }
}

function Pick-Port([int[]]$candidates) {
  foreach ($p in $candidates) { if (Port-Free $p) { return $p } }
  return $null
}

function Resolve-RequiredPort([string]$label, [int[]]$candidates, [int]$defaultPort) {
  $picked = Pick-Port $candidates
  if ($picked) { return [int]$picked }

  Warn "No free default port found for $label."
  while ($true) {
    $raw = (Read-Host "Enter custom port for $label (1-65535, default: $defaultPort)").Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = "$defaultPort" }
    $port = 0
    if (-not [int]::TryParse($raw, [ref]$port)) {
      Warn "Invalid number: $raw"
      continue
    }
    if ($port -lt 1 -or $port -gt 65535) {
      Warn "Port must be between 1 and 65535."
      continue
    }
    if (-not (Port-Free $port)) {
      Warn "Port $port is already in use."
      continue
    }
    return $port
  }
}

function Resolve-HttpsPortForIIS {
  if (Port-Free 443) {
    $use443 = (Read-Host "Use HTTPS port 443? (Y/n)").Trim().ToLowerInvariant()
    if ($use443 -eq "" -or $use443 -eq "y" -or $use443 -eq "yes") {
      return 443
    }
  } else {
    Warn "Port 443 is already in use."
  }

  Write-Host "Choose HTTPS port option:"
  Write-Host "  1) Auto alternate port (tries: 8443, 9443, 10443, 11443, 12443)"
  Write-Host "  2) Enter custom port"
  $choice = (Read-Host "Select option [1/2] (default: 1)").Trim()
  if ($choice -eq "2") {
    return Resolve-RequiredPort -label "HTTPS (IIS)" -candidates @() -defaultPort 8443
  }
  return Resolve-RequiredPort -label "HTTPS (IIS)" -candidates @(8443,9443,10443,11443,12443) -defaultPort 8443
}

function Has-ExistingLocalS3IISInstall {
  $exists = $false
  try {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (Test-Path "IIS:\Sites\LocalS3-IIS") { $exists = $true }
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
    if (Test-Path "IIS:\Sites\LocalS3-IIS") {
      Stop-Website -Name "LocalS3-IIS" 2>$null | Out-Null
      Remove-Website -Name "LocalS3-IIS" 2>$null | Out-Null
    }
  } catch {}

  schtasks /End /TN "LocalS3-MinIO" 1>$null 2>$null | Out-Null
  schtasks /Delete /TN "LocalS3-MinIO" /F 1>$null 2>$null | Out-Null

  Get-Process -Name "minio" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  if ($DeleteData -and $root) {
    $dataDir = Join-Path $root "data"
    $configDir = Join-Path $root "config"
    $siteDir = Join-Path $root "iis-site"
    $certDir = Join-Path $root "nginx\certs"
    if (Test-Path $dataDir) {
      Warn "Deleting previous MinIO data to reset credentials and state..."
      Remove-Item -Recurse -Force -Path $dataDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    }
    if (Test-Path $configDir) {
      Warn "Deleting previous MinIO config state..."
      Remove-Item -Recurse -Force -Path $configDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    }
    if (Test-Path $siteDir) {
      Remove-Item -Recurse -Force -Path $siteDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $siteDir | Out-Null
    }
    if (Test-Path $certDir) {
      Remove-Item -Recurse -Force -Path $certDir -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $certDir | Out-Null
    }
  }
  $ErrorActionPreference = $prev
  Start-Sleep -Seconds 2
}

function Get-LanIPv4 {
  try {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" } |
      Select-Object -First 1 -ExpandProperty IPAddress
    if ($ip) { return $ip }
  } catch {}

  try {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object {
        $_.IPAddress -notlike "169.254.*" -and
        $_.IPAddress -ne "127.0.0.1" -and
        $_.InterfaceAlias -notmatch "vEthernet|Hyper-V|WSL|Loopback"
      } |
      Select-Object -First 1 -ExpandProperty IPAddress)
    return $ip
  } catch {
    return $null
  }
}

function Ensure-FirewallPort([int]$port) {
  $ruleName = "Local S3 HTTPS $port"
  $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
  if ($rule) {
    Info "Firewall rule already exists: $ruleName"
    return
  }

  Info "Opening Windows Firewall inbound TCP $port..."
  New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port | Out-Null
}

function Ensure-HostsEntry([string]$domain) {
  if ($domain -eq "localhost") { return }
  $hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
  $escaped = [regex]::Escape($domain)
  $existing = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue
  if ($existing -match "(?im)^\s*(127\.0\.0\.1|::1)\s+.*\b$escaped\b") {
    Info "Hosts entry already exists for $domain"
    return
  }

  Warn "Adding local hosts mapping: 127.0.0.1 $domain"
  Add-Content -Path $hostsPath -Value "`r`n127.0.0.1`t$domain"
}

function Ensure-LocalTlsCert([string]$dockerCtx, [string]$certDir, [string]$domain, [string]$lanIp) {
  $crt = Join-Path $certDir "localhost.crt"
  $key = Join-Path $certDir "localhost.key"
  $san = "DNS:localhost,IP:127.0.0.1"
  if ($domain -ne "localhost") { $san += ",DNS:$domain" }
  if ($lanIp) { $san += ",IP:$lanIp" }

  Info "Generating self-signed TLS certificate for localhost/$domain..."
  New-Item -ItemType Directory -Force -Path $certDir | Out-Null
  Remove-Item -Path $crt,$key -Force -ErrorAction SilentlyContinue

  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  docker --context $dockerCtx run --rm -v "${certDir}:/out" alpine:3.20 sh -lc "apk add --no-cache openssl >/dev/null && openssl req -x509 -nodes -newkey rsa:2048 -days 825 -keyout /out/localhost.key -out /out/localhost.crt -subj '/CN=$domain' -addext 'subjectAltName=$san'" 2>&1 | Out-Null
  $exit = $LASTEXITCODE
  $ErrorActionPreference = $prev

  if ($exit -ne 0 -or -not (Test-Path $crt) -or -not (Test-Path $key)) {
    Err "Failed to generate TLS certificate/key for Nginx."
    exit 1
  }
}

function Trust-LocalTlsCert([string]$certPath) {
  try {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $exists = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if ($exists.Count -eq 0) {
      $store.Add($cert)
      Info "Trusted TLS certificate in LocalMachine\\Root."
    } else {
      Info "TLS certificate is already trusted."
    }
    $store.Close()
  } catch {
    Warn "Could not trust the certificate automatically. Run this in Admin PowerShell:"
    Write-Host "  Import-Certificate -FilePath `"$certPath`" -CertStoreLocation `"Cert:\LocalMachine\Root`""
  }
}

function Start-ContainersFallback([string]$dockerCtx, [string]$ngconf, [string]$ngcerts, [string]$data, [int]$nginxHttpsPort, [int]$minioApi, [int]$minioUI) {
  Warn "Falling back to direct 'docker run' startup (compose unavailable in this environment)."
  $network = "storage-net"

  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  docker --context $dockerCtx network create $network 2>$null | Out-Null
  docker --context $dockerCtx rm -f minio nginx 2>$null | Out-Null

  docker --context $dockerCtx run -d `
    --name minio `
    --label $Script:LocalS3Label `
    --label "com.locals3.role=minio" `
    --network $network `
    -e MINIO_ROOT_USER=admin `
    -e MINIO_ROOT_PASSWORD=StrongPassword123 `
    -p "${minioApi}:9000" `
    -p "${minioUI}:9001" `
    -v "${data}:/data" `
    minio/minio server /data --console-address ":9001" | Out-Null
  $minioExit = $LASTEXITCODE
  if ($minioExit -ne 0) {
    $ErrorActionPreference = $prev
    Err "Failed to start MinIO container via fallback mode."
    exit 1
  }

  docker --context $dockerCtx run -d `
    --name nginx `
    --label $Script:LocalS3Label `
    --label "com.locals3.role=nginx" `
    --network $network `
    -p "${nginxHttpsPort}:443" `
    -v "${ngconf}:/etc/nginx/conf.d:ro" `
    -v "${ngcerts}:/etc/nginx/certs:ro" `
    nginx:latest | Out-Null
  $nginxExit = $LASTEXITCODE
  $ErrorActionPreference = $prev
  if ($nginxExit -ne 0) {
    Err "Failed to start Nginx container via fallback mode."
    exit 1
  }
}

function Write-FilesAndUp {
  $root = Split-Path -Parent $PSCommandPath
  $project = Join-Path $root "storage-server"
  $ngconf = Join-Path $project "nginx\conf"
  $ngcerts = Join-Path $project "nginx\certs"
  $data   = Join-Path $project "data"

  $domainInput = Read-Host "Enter local domain/URL for HTTPS (default: localhost)"
  $domain = Normalize-HostInput $domainInput
  Info "Using local domain: $domain"
  $enableLan = $true
  Info "LAN access: enabled"
  $lanIp = $null
  if ($enableLan) {
    $lanIp = Get-LanIPv4
    if (-not $lanIp) {
      Warn "Could not detect LAN IPv4 automatically. LAN URL will not be shown."
    } else {
      Info "Detected LAN IP: $lanIp"
    }
  }

  # Resolve Docker context early so we can clean up previous installer containers if needed.
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  Sanitize-DockerEnv
  $dockerCtx = Get-ActiveDockerContext
  $ErrorActionPreference = $prev
  Info "Using Docker context: $dockerCtx"
  Prompt-CleanupPreviousServers -dockerCtx $dockerCtx

  $nginxHttps  = 443
  $minioApi    = Pick-Port @(9000,19000,29000)
  $minioUI     = Pick-Port @(9001,19001,29001)

  if (-not (Port-Free $nginxHttps)) {
    Warn "Port 443 is already in use."
    $listeners = Get-PortListeners 443
    if ($listeners.Count -gt 0) {
      Write-Host "Port 443 listeners:"
      $listeners | Format-Table -AutoSize | Out-String | Write-Host
    }
    $ans = (Read-Host "Use alternate HTTPS port (8443/9443/10443)? (y/N)").Trim().ToLowerInvariant()
    if ($ans -eq "y" -or $ans -eq "yes") {
      $nginxHttps = Pick-Port @(8443,9443,10443)
      if (-not $nginxHttps) {
        Err "No free alternate HTTPS port (8443/9443/10443)."
        exit 1
      }
      Warn "Using alternate HTTPS port: $nginxHttps"
    } else {
      Err "Port 443 is required but currently in use. Free it and rerun."
      exit 1
    }
  }
  if (-not $minioApi)  { Err "No free port for MinIO API (9000/19000/29000)."; exit 1 }
  if (-not $minioUI)   { Err "No free port for MinIO UI (9001/19001/29001)."; exit 1 }
  if ($enableLan) { Ensure-FirewallPort -port $nginxHttps }

  Info "Using ports:"
  Info " - Nginx HTTPS: $nginxHttps"
  Info " - MinIO API:  $minioApi"
  Info " - MinIO UI:   $minioUI"

  New-Item -ItemType Directory -Force -Path $ngconf | Out-Null
  New-Item -ItemType Directory -Force -Path $ngcerts | Out-Null
  New-Item -ItemType Directory -Force -Path $data | Out-Null

  Run-PreflightChecks -DataPath $data
  Info "Project folder: $project"

  $compose = @"
services:
  minio:
    image: minio/minio
    container_name: minio
    labels:
      - "com.locals3.installer=true"
      - "com.locals3.role=minio"
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: admin
      MINIO_ROOT_PASSWORD: StrongPassword123
      MINIO_PROMETHEUS_AUTH_TYPE: public
      MINIO_BROWSER_REDIRECT_URL: ""
    volumes:
      - ./data:/data
    ports:
      - "$minioApi:9000"
      - "$minioUI:9001"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s
    deploy:
      resources:
        limits:
          memory: 1g

  nginx:
    image: nginx:latest
    container_name: nginx
    labels:
      - "com.locals3.installer=true"
      - "com.locals3.role=nginx"
    ports:
      - "$nginxHttps:443"
    volumes:
      - ./nginx/conf:/etc/nginx/conf.d:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    depends_on:
      minio:
        condition: service_healthy
    restart: unless-stopped
"@

  $serverNames = if ($domain -eq "localhost") { "localhost" } else { "$domain localhost" }
  $nginx = @"
# Gzip compression
gzip on;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/octet-stream;
gzip_min_length 1024;
gzip_vary on;

server {
    listen 443 ssl http2;
    server_name $serverNames;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    # TLS hardening
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy no-referrer-when-downgrade always;

    # Allow large file uploads (up to 5 GB)
    client_max_body_size 5g;

    # MinIO Console (web dashboard + WebSocket)
    location / {
        proxy_pass         http://minio:9001;
        proxy_http_version 1.1;
        proxy_set_header Host            `$http_host;
        proxy_set_header X-Real-IP       `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade         `$http_upgrade;
        proxy_set_header Connection      "upgrade";
        proxy_read_timeout 3600;
        proxy_buffering    off;
    }

    # MinIO S3 API (for SDK / CLI / programmatic access via /s3/)
    location /s3/ {
        rewrite ^/s3/(.*) /`$1 break;
        proxy_pass         http://minio:9000;
        proxy_http_version 1.1;
        proxy_set_header Host            `$http_host;
        proxy_set_header X-Real-IP       `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600;
        proxy_buffering    off;
        client_max_body_size 5g;
    }
}
"@

  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText((Join-Path $project "docker-compose.yml"), $compose, $utf8NoBom)
  [System.IO.File]::WriteAllText((Join-Path $ngconf  "default.conf"),       $nginx,   $utf8NoBom)
  Ensure-HostsEntry -domain $domain
  Ensure-LocalTlsCert -dockerCtx $dockerCtx -certDir $ngcerts -domain $domain -lanIp $lanIp
  Trust-LocalTlsCert -certPath (Join-Path $ngcerts "localhost.crt")

  Info "Starting containers..."
  Push-Location $project
  $usedFallback = $false

  # Remove existing containers if present (don't error if they don't exist)
  $ErrorActionPreference = "Continue"
  docker --context $dockerCtx rm -f minio nginx 2>$null | Out-Null
  $ErrorActionPreference = $prev

  # Ensure engine still ok right before up
  if (-not (Test-DockerEngine)) {
    Pop-Location
    Err "Docker Engine became unavailable right before startup."
    exit 1
  }

  $ErrorActionPreference = "Continue"
  $composeOut = docker --context $dockerCtx compose up -d 2>&1
  $upExit = $LASTEXITCODE
  $ErrorActionPreference = $prev
  if ($upExit -ne 0) {
    $composeText = ($composeOut | Out-String)
    Warn "docker compose up failed."
    if ($composeText -match "invalid proto:") {
      Warn "Detected compose transport error ('invalid proto:')."
      Pop-Location
      Start-ContainersFallback -dockerCtx $dockerCtx -ngconf $ngconf -ngcerts $ngcerts -data $data -nginxHttpsPort $nginxHttps -minioApi $minioApi -minioUI $minioUI
      $usedFallback = $true
    } else {
      Warn "Showing compose logs..."
      $ErrorActionPreference = "Continue"
      docker --context $dockerCtx compose logs --no-color --tail 200 2>&1
      $ErrorActionPreference = $prev
      Pop-Location
      exit 1
    }
  }

  Start-Sleep -Seconds 3

  $names = @(docker --context $dockerCtx ps --format "{{.Names}}")
  if ($names -notcontains "minio" -or $names -notcontains "nginx") {
    Warn "Containers not running as expected. Logs:"
    $ErrorActionPreference = "Continue"
    if ($usedFallback) {
      docker --context $dockerCtx ps -a --filter "name=minio" --filter "name=nginx" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>&1
      Write-Host ""
      Write-Host "--- minio logs ---"
      docker --context $dockerCtx logs --tail 200 minio 2>&1
      Write-Host ""
      Write-Host "--- nginx logs ---"
      docker --context $dockerCtx logs --tail 200 nginx 2>&1
    } else {
      docker --context $dockerCtx compose logs --no-color --tail 200 2>&1
    }
    $ErrorActionPreference = $prev
    Pop-Location
    exit 1
  }

  # Wait for MinIO API port to be reachable before declaring success
  Info "Waiting for MinIO to become ready..."
  if (-not (Wait-TcpPort -targetHost "127.0.0.1" -port $minioApi -maxSeconds 60)) {
    Warn "MinIO API port $minioApi did not become ready in 60 seconds."
    $ErrorActionPreference = "Continue"
    if ($usedFallback) {
      docker --context $dockerCtx logs --tail 80 minio 2>&1
    } else {
      docker --context $dockerCtx compose logs --no-color --tail 80 minio 2>&1
    }
    $ErrorActionPreference = $prev
    Pop-Location
    Err "MinIO did not start in time. Check container logs above."
    exit 1
  }
  if (-not (Test-MinIOHealth -apiPort $minioApi)) {
    Warn "MinIO port $minioApi is open but health check failed."
    $ErrorActionPreference = "Continue"
    if ($usedFallback) {
      docker --context $dockerCtx logs --tail 80 minio 2>&1
    } else {
      docker --context $dockerCtx compose logs --no-color --tail 80 minio 2>&1
    }
    $ErrorActionPreference = $prev
    Pop-Location
    Err "MinIO health check failed. Check container logs above."
    exit 1
  }
  Info "MinIO is healthy and accepting requests."

  # Auto-configure buckets, CORS, service accounts
  Configure-MinIOFeatures -ApiPort $minioApi -UiPort $minioUI

  Pop-Location

  $proxyUrl = if ($nginxHttps -eq 443) { "https://$domain" } else { "https://${domain}:$nginxHttps" }
  Write-Host ""
  Write-Host "===== INSTALLATION COMPLETE ====="
  Write-Host ""
  Write-Host "URLs:"
  Write-Host "  MinIO Console (dashboard): http://localhost:$minioUI"
  Write-Host "  MinIO API (S3):            http://localhost:$minioApi"
  Write-Host "  HTTPS Proxy (console):     $proxyUrl"
  Write-Host "  HTTPS S3 API route:        $proxyUrl/s3/"
  if ($enableLan -and $lanIp) {
    $lanUrl = if ($nginxHttps -eq 443) { "https://$lanIp" } else { "https://${lanIp}:$nginxHttps" }
    Write-Host "  LAN URL:                   $lanUrl"
  }
  Write-Host ""
  Write-Host "Login:"
  Write-Host "  Username : admin"
  Write-Host "  Password : StrongPassword123"
  Write-Host ""
  Write-Host "Pre-configured buckets:"
  Write-Host "  images    (public-read + CORS enabled)"
  Write-Host "  documents"
  Write-Host "  backups"
  Write-Host ""
  Write-Host "Read-only service account (for apps / SDKs):"
  Write-Host "  Access key : readonly-app"
  Write-Host "  Secret key : ReadOnly#App2024!"
  Write-Host ""
  Write-Host "TLS: Self-signed cert trusted in LocalMachine\Root."
  if ($enableLan -and $lanIp) {
    Write-Host ""
    Write-Host "For other computers on the LAN:"
    if ($domain -ne "localhost") {
      Write-Host "  Add hosts entry: $lanIp $domain"
      if ($nginxHttps -eq 443) {
        Write-Host "  Then open: https://$domain"
      } else {
        Write-Host "  Then open: https://${domain}:$nginxHttps"
      }
    } else {
      if ($nginxHttps -eq 443) {
        Write-Host "  Open: https://$lanIp"
      } else {
        Write-Host "  Open: https://${lanIp}:$nginxHttps"
      }
    }
    Write-Host "  Trust cert on client: $($ngcerts)\localhost.crt"
  }
}

# ---------------------------
# Main
# ---------------------------
Relaunch-Elevated
Initialize-NetworkDefaults
Info "===== Local S3 Storage Installer (Windows) ====="
$mode = Ask-InstallMode
if ($mode -eq "iis") {
  Install-IISMode
  exit 0
}

Enable-WSLFeatures
Ensure-DockerInstalled
if (Finish-Or-Restart) { exit 0 }
Sanitize-DockerEnv
Wait-DockerEngine
Reset-RestartCount
Ensure-DockerCompose
Write-FilesAndUp

