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

function Info($m){ Write-Host "[INFO] $m" }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Err ($m){ Write-Host "[ERROR] $m" -ForegroundColor Red }

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

function Test-TcpPort([string]$host, [int]$port, [int]$timeoutMs = 1500) {
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $ar = $client.BeginConnect($host, $port, $null, $null)
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

function Wait-TcpPort([string]$host, [int]$port, [int]$maxSeconds = 30) {
  $elapsed = 0
  while ($elapsed -lt $maxSeconds) {
    if (Test-TcpPort -host $host -port $port) { return $true }
    Start-Sleep -Seconds 1
    $elapsed += 1
  }
  return $false
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
    "IIS-ISAPIExtensions","IIS-ISAPIFilter","IIS-ManagementConsole"
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

function Ensure-MinIONative([string]$root,[int]$apiPort,[int]$uiPort) {
  $binDir = Join-Path $root "minio"
  $dataDir = Join-Path $root "data"
  $exe = Join-Path $binDir "minio.exe"
  New-Item -ItemType Directory -Force -Path $binDir,$dataDir | Out-Null
  if (-not (Test-Path $exe)) {
    Info "Downloading MinIO server binary..."
    Invoke-WebRequest -Uri "https://dl.min.io/server/minio/release/windows-amd64/minio.exe" -OutFile $exe
  }

  [Environment]::SetEnvironmentVariable("MINIO_ROOT_USER","admin","Machine")
  [Environment]::SetEnvironmentVariable("MINIO_ROOT_PASSWORD","StrongPassword123","Machine")

  $taskName = "LocalS3-MinIO"
  $cmd = "`"$exe`" server `"$dataDir`" --address `":$apiPort`" --console-address `":$uiPort`""
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
  schtasks /Run /TN $taskName 1>$null 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Warn "MinIO task created but could not be started immediately. It will run at next startup."
  }
  $ErrorActionPreference = $prev

  if (-not (Wait-TcpPort -host "127.0.0.1" -port $uiPort -maxSeconds 45)) {
    Warn "MinIO console port $uiPort did not become ready in time."
    Warn "Task status:"
    schtasks /Query /TN $taskName /V /FO LIST 2>$null | Out-String | Write-Host
    Err "MinIO service is not reachable yet. Fix MinIO startup and rerun."
    exit 1
  }
}

function Ensure-IISProxyMode([string]$domain,[string]$siteRoot,[string]$certPath,[string]$keyPath,[int]$httpsPort,[int]$targetPort,[string]$lanIp) {
  Import-Module WebAdministration
  New-Item -ItemType Directory -Force -Path $siteRoot | Out-Null
  $webConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="ReverseProxyInboundRule1" stopProcessing="true">
          <match url="(.*)" />
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
  } catch {
    Err "IIS reverse proxy is not available (ARR/URL Rewrite missing)."
    Warn "Install these IIS extensions, then rerun in IIS mode:"
    Write-Host "  - URL Rewrite"
    Write-Host "  - Application Request Routing (ARR)"
    exit 1
  }

  $certDns = @("localhost",$domain) | Select-Object -Unique
  $cert = New-SelfSignedCertificate -DnsName $certDns -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(2)
  $thumb = $cert.Thumbprint
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

  if (-not (Wait-TcpPort -host "127.0.0.1" -port $httpsPort -maxSeconds 30)) {
    Err "IIS HTTPS listener on port $httpsPort is not reachable."
    Warn "IIS site state:"
    Get-Website -Name "LocalS3-IIS" | Format-List * | Out-String | Write-Host
    Warn "Check if another app is blocking port $httpsPort."
    exit 1
  }

  if ($domain -ne "localhost") { Ensure-HostsEntry -domain $domain }
  if ($lanIp) { Ensure-FirewallPort -port $httpsPort }
}

function Install-IISMode {
  $root = Join-Path (Split-Path -Parent $PSCommandPath) "storage-server"
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

  $httpsPort = 443
  if (-not (Port-Free $httpsPort)) {
    Warn "Port 443 is already in use."
    $httpsPort = Pick-Port @(8443,9443,10443)
    if (-not $httpsPort) { Err "No free HTTPS port available."; exit 1 }
    Warn "Using alternate HTTPS port: $httpsPort"
  }

  $apiPort = Pick-Port @(9000,19000,29000)
  $uiPort = Pick-Port @(9001,19001,29001)
  if (-not $apiPort -or -not $uiPort) { Err "No free MinIO ports available."; exit 1 }

  Ensure-IISInstalled
  Ensure-MinIONative -root $root -apiPort $apiPort -uiPort $uiPort
  $crt = Join-Path $certDir "localhost.crt"
  $key = Join-Path $certDir "localhost.key"
  Ensure-IISProxyMode -domain $domain -siteRoot $siteRoot -certPath $crt -keyPath $key -httpsPort $httpsPort -targetPort $uiPort -lanIp $lanIp

  Write-Host ""
  Write-Host "===== INSTALLATION COMPLETE (IIS MODE) ====="
  Write-Host "MinIO Console (direct): http://localhost:$uiPort"
  Write-Host "MinIO API (direct):     http://localhost:$apiPort"
  if ($httpsPort -eq 443) {
    Write-Host "IIS Proxy URL:          https://$domain"
  } else {
    Write-Host "IIS Proxy URL:          https://${domain}:$httpsPort"
  }
  if ($enableLan -and $lanIp) {
    if ($httpsPort -eq 443) {
      Write-Host "LAN URL:                https://$lanIp"
    } else {
      Write-Host "LAN URL:                https://${lanIp}:$httpsPort"
    }
    Write-Host "For DNS: map $domain -> $lanIp"
  }
  Write-Host ""
  Write-Host "Login:"
  Write-Host "  Username: admin"
  Write-Host "  Password: StrongPassword123"
}

function Enable-WSLFeatures {
  Info "Checking Windows features required for WSL2..."
  $needRestart = $false

  $wsl = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State
  if ($wsl -ne "Enabled") {
    Info "Enabling Microsoft-Windows-Subsystem-Linux..."
    dism /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart | Out-Null
    $needRestart = $true
  }

  $vmp = (Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State
  if ($vmp -ne "Enabled") {
    Info "Enabling VirtualMachinePlatform..."
    dism /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart | Out-Null
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

  Err "Docker CLI not found."
  Warn "Please install Docker Desktop manually, then rerun this script."
  Write-Host "Download URL:"
  Write-Host "  https://www.docker.com/products/docker-desktop/"
  Write-Host "Direct Windows installer:"
  Write-Host "  https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
  exit 1
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

function Wait-DockerEngine {
  Info "Checking Docker Engine availability..."
  if (Test-DockerEngine) {
    Info "Docker Engine is ready."
    return
  }

  Warn "Docker Engine not reachable. Attempting to start Docker Desktop..."
  Start-DockerDesktop

  $maxSeconds = 180
  $step = 5
  $elapsed = 0

  while ($elapsed -lt $maxSeconds) {
    Start-Sleep -Seconds $step
    $elapsed += $step
    if (Test-DockerEngine) {
      Info "Docker Engine is ready."
      return
    }
  }

  Err "Docker Engine is still NOT reachable after waiting."
  Warn "Run these checks (in Admin PowerShell):"
  Write-Host "  wsl --status"
  Write-Host "  wsl --install"
  Write-Host "  wsl --shutdown"
  Warn "Then open Docker Desktop and wait until it says 'Engine running'."
  Warn "If virtualization is disabled, enable it in BIOS (Intel VT-x / AMD SVM)."
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
    Ensure-FirewallPort -port 443
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
    volumes:
      - ./data:/data
    ports:
      - "$minioApi:9000"
      - "$minioUI:9001"
    restart: unless-stopped

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
      - minio
    restart: unless-stopped
"@

  $serverNames = if ($domain -eq "localhost") { "localhost" } else { "$domain localhost" }
  $nginx = @"
server {
    listen 443 ssl;
    server_name $serverNames;
    ssl_certificate /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    location / {
        proxy_pass http://minio:9001;
        proxy_http_version 1.1;
        proxy_set_header Host `$http_host;
        proxy_set_header X-Real-IP `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade `$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
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

  Pop-Location

  Write-Host ""
  Write-Host "===== INSTALLATION COMPLETE ====="
  Write-Host "MinIO Console: http://localhost:$minioUI"
  Write-Host "MinIO API:     http://localhost:$minioApi"
  $proxyUrl = if ($nginxHttps -eq 443) { "https://$domain" } else { "https://${domain}:$nginxHttps" }
  Write-Host "Proxy URL:     $proxyUrl"
  if ($enableLan -and $lanIp) {
    $lanUrl = if ($nginxHttps -eq 443) { "https://$lanIp" } else { "https://${lanIp}:$nginxHttps" }
    Write-Host "LAN URL:       $lanUrl"
  }
  Write-Host ""
  Write-Host "TLS note:"
  Write-Host "  Self-signed cert has been trusted in LocalMachine\\Root."
  Write-Host ""
  Write-Host "Login:"
  Write-Host "  Username: admin"
  Write-Host "  Password: StrongPassword123"
  Write-Host ""
  Write-Host "Next: open MinIO Console, create bucket: images"
  if ($enableLan -and $lanIp) {
    Write-Host ""
    Write-Host "For other computers:"
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
    Write-Host "  Trust cert file on client (optional, avoids warning):"
    Write-Host "  $($ngcerts)\localhost.crt"
  }
}

# ---------------------------
# Main
# ---------------------------
Relaunch-Elevated
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

