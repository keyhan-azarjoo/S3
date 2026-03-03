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

function Get-ActiveDockerContext {
  if (-not (Has-Cmd "docker")) {
    return ""
  }

  try {
    $ctx = (& docker context show 2>$null | Out-String).Trim()
    if ($ctx) {
      return $ctx
    }
  } catch {}

  if ($env:DOCKER_CONTEXT) {
    return $env:DOCKER_CONTEXT
  }

  return "default"
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

  if ($value -notmatch '^((\d{1,3}\.){3}\d{1,3}|[a-z0-9]([a-z0-9\.-]*[a-z0-9])?)$') {
    Err "Invalid domain/host input: '$raw'"
    Err "Use values like: localhost, <server-ip>, mystorage.local, mystorage.com, or https://mystorage.com"
    exit 1
  }

  return $value
}

function Test-IPv4Literal([string]$value) {
  return $value -match '^(\d{1,3}\.){3}\d{1,3}$'
}

function Test-PrivateIPv4([string]$ip) {
  return (
    $ip -like "10.*" -or
    $ip -like "127.*" -or
    $ip -like "169.254.*" -or
    $ip -like "192.168.*" -or
    $ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.'
  )
}

function Resolve-BrowserSessionDuration {
  return "3650d"
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

function Ask-InstallMode {
  Write-Host ""
  Write-Host "Choose installation mode:"
  Write-Host "  1) IIS (native MinIO + IIS reverse proxy)"
  Write-Host "  2) Docker (MinIO + Nginx containers)"
  $choice = (Read-Host "Select 1 or 2 (default: 1)").Trim()
  if ($choice -eq "2") { return "docker" }
  return "iis"
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

function Get-PublicIPv4 {
  try {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Manual -ErrorAction SilentlyContinue |
      Where-Object {
        $_.IPAddress -and
        $_.IPAddress -ne "127.0.0.1" -and
        $_.IPAddress -notlike "169.254.*" -and
        -not (Test-PrivateIPv4 $_.IPAddress) -and
        $_.InterfaceAlias -notmatch "vEthernet|Hyper-V|WSL|Loopback"
      } |
      Select-Object -First 1 -ExpandProperty IPAddress
    if ($ip) { return $ip }
  } catch {}

  try {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object {
        $_.IPAddress -and
        $_.IPAddress -ne "127.0.0.1" -and
        $_.IPAddress -notlike "169.254.*" -and
        -not (Test-PrivateIPv4 $_.IPAddress) -and
        $_.InterfaceAlias -notmatch "vEthernet|Hyper-V|WSL|Loopback"
      } |
      Select-Object -First 1 -ExpandProperty IPAddress
    return $ip
  } catch {
    return $null
  }
}

function Resolve-InstallHost([string]$prompt) {
  $domainInput = Read-Host $prompt
  $domain = Normalize-HostInput $domainInput

  if ($domain -eq "localhost") {
    $publicIp = Get-PublicIPv4
    if ($publicIp) {
      $usePublicIp = (Read-Host "Detected public/static IP $publicIp. Use it instead of localhost? (Y/n)").Trim().ToLowerInvariant()
      if ([string]::IsNullOrWhiteSpace($usePublicIp) -or $usePublicIp -eq "y" -or $usePublicIp -eq "yes") {
        $domain = $publicIp
      }
    }
  }

  return $domain
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
  if ($domain -eq "localhost" -or (Test-IPv4Literal $domain)) { return }
  $hostsPath = Join-Path $env:SystemRoot "System32\\drivers\\etc\\hosts"
  $escaped = [regex]::Escape($domain)
  $existing = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue
  if ($existing -match "(?im)^\\s*(127\\.0\\.0\\.1|::1)\\s+.*\\b$escaped\\b") {
    Info "Hosts entry already exists for $domain"
    return
  }

  Warn "Adding local hosts mapping: 127.0.0.1 $domain"
  Add-Content -Path $hostsPath -Value "`r`n127.0.0.1`t$domain"
}
