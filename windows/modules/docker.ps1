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


function Ensure-LocalTlsCert([string]$dockerCtx, [string]$certDir, [string]$domain, [string]$lanIp) {
  $crt = Join-Path $certDir "localhost.crt"
  $key = Join-Path $certDir "localhost.key"
  $san = "DNS:localhost,IP:127.0.0.1"
  if ($domain -ne "localhost") {
    if (Test-IPv4Literal $domain) { $san += ",IP:$domain" } else { $san += ",DNS:$domain" }
  }
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

function Start-ContainersFallback([string]$dockerCtx, [string]$ngconf, [string]$ngcerts, [string]$minioVolume, [string]$minioImage, [int]$httpsPort, [int]$consoleHttpsPort, [int]$minioApi, [int]$minioUI, [string]$consoleBrowserUrl, [string]$browserSessionDuration) {
  Warn "Falling back to direct 'docker run' startup (compose unavailable in this environment)."
  $network = "storage-net"

  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  docker --context $dockerCtx network create $network 2>$null | Out-Null
  docker --context $dockerCtx volume create $minioVolume 2>$null | Out-Null
  docker --context $dockerCtx rm -f minio console nginx 2>$null | Out-Null

  $minioArgs = @(
    "--context", $dockerCtx, "run", "-d",
    "--name", "minio",
    "--label", $Script:LocalS3Label,
    "--label", "com.locals3.role=minio",
    "--network", $network,
    "-e", "MINIO_ROOT_USER=admin",
    "-e", "MINIO_ROOT_PASSWORD=StrongPassword123",
    "-e", "MINIO_API_PORT=9000",
    "-e", "MINIO_CONSOLE_PORT=9001",
    "-e", "MINIO_ADMIN_CONSOLE_PORT=9002",
    "-e", "MINIO_BROWSER_REDIRECT_URL=$consoleBrowserUrl",
    "-e", "MINIO_BROWSER_SESSION_DURATION=$browserSessionDuration",
    "-p", "${minioApi}:9000",
    "-p", "${minioUI}:9001",
    "-v", "${minioVolume}:/data",
    $minioImage
  )
  docker @minioArgs | Out-Null
  $minioExit = $LASTEXITCODE
  if ($minioExit -ne 0) {
    $ErrorActionPreference = $prev
    Err "Failed to start MinIO container via fallback mode."
    exit 1
  }

  $nginxArgs = @(
    "--context", $dockerCtx, "run", "-d",
    "--name", "nginx",
    "--label", $Script:LocalS3Label,
    "--label", "com.locals3.role=nginx",
    "--network", $network,
    "-p", "${httpsPort}:443",
    "-p", "${consoleHttpsPort}:4443",
    "-v", "${ngconf}:/etc/nginx/conf.d:ro",
    "-v", "${ngcerts}:/etc/nginx/certs:ro",
    "nginx:latest"
  )
  docker @nginxArgs | Out-Null
  $nginxExit = $LASTEXITCODE
  $ErrorActionPreference = $prev
  if ($nginxExit -ne 0) {
    Err "Failed to start Nginx container via fallback mode."
    exit 1
  }
}

function Write-FilesAndUp {
  $project = Join-Path $env:ProgramData "LocalS3\storage-server"
  $ngconf = Join-Path $project "nginx\conf"
  $ngcerts = Join-Path $project "nginx\certs"
  $data = Join-Path $project "data"
  $minioVolume = "locals3-minio-data"
  $minioImage = "firstfinger/minio:latest-amd64"

  $domain = Resolve-InstallHost "Enter local domain/URL for HTTPS (default: localhost)"
  Info "Using local domain: $domain"
  $browserSessionDuration = Resolve-BrowserSessionDuration
  Info "Web session/share-link max duration: $browserSessionDuration"

  $enableLan = $true
  Info "LAN access: enabled"
  $lanIp = Get-LanIPv4
  if ($lanIp) { Info "Detected LAN IP: $lanIp" } else { Warn "Could not detect LAN IPv4 automatically. LAN URL will not be shown." }

  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  Sanitize-DockerEnv
  $dockerCtx = Get-ActiveDockerContext
  $ErrorActionPreference = $prev
  Info "Using Docker context: $dockerCtx"
  Prompt-CleanupPreviousServers -dockerCtx $dockerCtx

  $httpsPort = 443
  if (-not (Port-Free $httpsPort)) {
    Warn "Port 443 is already in use."
    $listeners = Get-PortListeners 443
    if ($listeners.Count -gt 0) {
      Write-Host "Port 443 listeners:"
      $listeners | Format-Table -AutoSize | Out-String | Write-Host
    }
    $httpsPort = Pick-Port @(8443,9443,10443)
    if (-not $httpsPort) {
      Err "Port 443 is busy and no free alternate HTTPS port is available (8443/9443/10443)."
      exit 1
    }
    Warn "Using alternate HTTPS port: $httpsPort"
  }

  $minioApi = Pick-Port @(9000,19000,29000)
  $minioUI = Pick-Port @(9001,19001,29001)
  if (-not $minioApi) { Err "No free port for MinIO API (9000/19000/29000)."; exit 1 }
  if (-not $minioUI) { Err "No free port for MinIO UI (9001/19001/29001)."; exit 1 }

  $consoleCandidates = @(9443,10443,11443,12443,13443) | Where-Object { $_ -ne $httpsPort }
  $consoleHttpsPort = Resolve-RequiredPort -label "MinIO Console HTTPS" -candidates $consoleCandidates -defaultPort ($httpsPort + 1000)

  if ($enableLan) {
    Ensure-FirewallPort -port $httpsPort
    Ensure-FirewallPort -port $consoleHttpsPort
  }

  $displayHost = if ($domain -eq "localhost" -and $lanIp) { $lanIp } else { $domain }
  $publicUrl = if ($httpsPort -eq 443) { "https://$displayHost" } else { "https://${displayHost}:$httpsPort" }
  $consoleBrowserUrl = if ($consoleHttpsPort -eq 80) { "http://$domain" } else { "http://${domain}:$consoleHttpsPort" }
  $consoleRedirectUrl = if ($domain -eq "localhost" -and $lanIp) { "" } else { $consoleBrowserUrl }

  Info "Using ports:"
  Info " - S3 API HTTPS: $httpsPort"
  Info " - Console HTTPS: $consoleHttpsPort"
  Info " - MinIO API:  $minioApi"
  Info " - MinIO UI:   $minioUI"

  New-Item -ItemType Directory -Force -Path $project,$ngconf,$ngcerts,$data | Out-Null
  Run-PreflightChecks -DataPath $data
  Info "Project folder: $project"

  $compose = @"
services:
  minio:
    image: $minioImage
    container_name: minio
    labels:
      - "com.locals3.installer=true"
      - "com.locals3.role=minio"
    environment:
      MINIO_ROOT_USER: admin
      MINIO_ROOT_PASSWORD: StrongPassword123
      MINIO_API_PORT: "9000"
      MINIO_CONSOLE_PORT: "9001"
      MINIO_ADMIN_CONSOLE_PORT: "9002"
      MINIO_PROMETHEUS_AUTH_TYPE: public
      MINIO_BROWSER_REDIRECT_URL: "$consoleRedirectUrl"
      MINIO_BROWSER_SESSION_DURATION: "$browserSessionDuration"
    volumes:
      - ${minioVolume}:/data
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

  nginx:
    image: nginx:latest
    container_name: nginx
    labels:
      - "com.locals3.installer=true"
      - "com.locals3.role=nginx"
    ports:
      - "$httpsPort:443"
      - "$consoleHttpsPort:4443"
    volumes:
      - ./nginx/conf:/etc/nginx/conf.d:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    depends_on:
      minio:
        condition: service_started
    restart: unless-stopped

volumes:
  ${minioVolume}:
"@

  $serverNames = if ($domain -eq "localhost") { "localhost" } else { "$domain localhost" }
  $nginx = @"
# Gzip compression
gzip on;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/octet-stream;
gzip_min_length 1024;
gzip_vary on;

server {
    listen 443 ssl;
    http2 on;
    server_name $serverNames;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy no-referrer-when-downgrade always;

    client_max_body_size 5g;

    location / {
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

server {
    listen 4443;
    server_name $serverNames;

    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy no-referrer-when-downgrade always;

    client_max_body_size 5g;

    location / {
        proxy_pass         http://minio:9002;
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
}
"@

  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText((Join-Path $project "docker-compose.yml"), $compose, $utf8NoBom)
  [System.IO.File]::WriteAllText((Join-Path $ngconf "default.conf"), $nginx, $utf8NoBom)

  Ensure-HostsEntry -domain $domain
  Ensure-LocalTlsCert -dockerCtx $dockerCtx -certDir $ngcerts -domain $domain -lanIp $lanIp
  Trust-LocalTlsCert -certPath (Join-Path $ngcerts "localhost.crt")

  Info "Starting containers..."
  Push-Location $project
  $usedFallback = $false

  $ErrorActionPreference = "Continue"
  docker --context $dockerCtx rm -f minio console nginx 2>$null | Out-Null
  $ErrorActionPreference = $prev

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
      Start-ContainersFallback -dockerCtx $dockerCtx -ngconf $ngconf -ngcerts $ngcerts -minioVolume $minioVolume -minioImage $minioImage -httpsPort $httpsPort -consoleHttpsPort $consoleHttpsPort -minioApi $minioApi -minioUI $minioUI -consoleBrowserUrl $consoleBrowserUrl -browserSessionDuration $browserSessionDuration
      $usedFallback = $true
      Push-Location $project
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

  Info "Waiting for MinIO to become ready..."
  if (-not (Wait-TcpPort -targetHost "127.0.0.1" -port $minioApi -maxSeconds 60)) {
    Warn "MinIO API port $minioApi did not become ready in 60 seconds."
    $ErrorActionPreference = "Continue"
    if ($usedFallback) { docker --context $dockerCtx logs --tail 80 minio 2>&1 } else { docker --context $dockerCtx compose logs --no-color --tail 80 minio 2>&1 }
    $ErrorActionPreference = $prev
    Pop-Location
    Err "MinIO did not start in time. Check container logs above."
    exit 1
  }
  if (-not (Test-MinIOHealth -apiPort $minioApi)) {
    Warn "MinIO port $minioApi is open but health check failed."
    $ErrorActionPreference = "Continue"
    if ($usedFallback) { docker --context $dockerCtx logs --tail 80 minio 2>&1 } else { docker --context $dockerCtx compose logs --no-color --tail 80 minio 2>&1 }
    $ErrorActionPreference = $prev
    Pop-Location
    Err "MinIO health check failed. Check container logs above."
    exit 1
  }
  Info "MinIO is healthy and accepting requests."

  Info "Waiting for MinIO Console to become ready..."
  if (-not (Wait-TcpPort -targetHost "127.0.0.1" -port $minioUI -maxSeconds 60)) {
    Warn "MinIO Console port $minioUI did not become ready in 60 seconds."
    $ErrorActionPreference = "Continue"
    if ($usedFallback) { docker --context $dockerCtx logs --tail 80 minio 2>&1 } else { docker --context $dockerCtx compose logs --no-color --tail 80 minio 2>&1 }
    $ErrorActionPreference = $prev
    Pop-Location
    Err "MinIO Console did not start in time. Check container logs above."
    exit 1
  }

  Configure-MinIOFeatures -ApiPort $minioApi -UiPort $minioUI
  Pop-Location

  Write-Host ""
  Write-Host "===== INSTALLATION COMPLETE ====="
  Write-Host ""
  Write-Host "URLs:"
  Write-Host "  MinIO Console:          $consoleBrowserUrl"
  Write-Host "  S3 API / Share links:   $publicUrl"
  Write-Host "  MinIO Console (direct): http://localhost:$minioUI"
  Write-Host "  MinIO API (direct):     http://localhost:$minioApi"
  if ($enableLan -and $lanIp) {
    $lanConsoleUrl = if ($consoleHttpsPort -eq 80) { "http://$lanIp" } else { "http://${lanIp}:$consoleHttpsPort" }
    $lanApiUrl = if ($httpsPort -eq 443) { "https://$lanIp" } else { "https://${lanIp}:$httpsPort" }
    Write-Host "  LAN Console:            $lanConsoleUrl"
    Write-Host "  LAN S3 API:             $lanApiUrl"
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
  Write-Host "TLS: Self-signed cert trusted in LocalMachine\\Root."
  if ($enableLan -and $lanIp) {
    Write-Host ""
    Write-Host "For other computers on the LAN:"
    if ($domain -ne "localhost") {
      Write-Host "  Add hosts entry: $lanIp $domain"
      if ($consoleHttpsPort -eq 80) { Write-Host "  Then open: http://$domain" } else { Write-Host "  Then open: http://${domain}:$consoleHttpsPort" }
      if ($httpsPort -eq 443) { Write-Host "  S3 API: https://$domain" } else { Write-Host "  S3 API: https://${domain}:$httpsPort" }
    } else {
      if ($consoleHttpsPort -eq 80) { Write-Host "  Open: http://$lanIp" } else { Write-Host "  Open: http://${lanIp}:$consoleHttpsPort" }
      if ($httpsPort -eq 443) { Write-Host "  S3 API: https://$lanIp" } else { Write-Host "  S3 API: https://${lanIp}:$httpsPort" }
    }
    Write-Host "  Trust cert on client: $($ngcerts)\\localhost.crt"
  }
}

function Invoke-LocalS3DockerPreparation {
  Enable-WSLFeatures
  Ensure-DockerInstalled
  if (Finish-Or-Restart) { return $false }
  Sanitize-DockerEnv
  Wait-DockerEngine
  Reset-RestartCount
  Ensure-DockerCompose
  return $true
}

function Invoke-LocalS3DockerSetup {
  if (-not (Invoke-LocalS3DockerPreparation)) { return }
  Write-FilesAndUp
}
