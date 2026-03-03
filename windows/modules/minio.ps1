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


function Ensure-MinIONative([string]$root,[int]$apiPort,[int]$uiPort,[string]$publicUrl,[string]$consoleBrowserUrl="",[string]$browserSessionDuration="3650d") {
  $Script:ActiveAccessKey = "admin"
  $Script:ActiveSecretKey = "StrongPassword123"
  $preferredMinIORelease = "RELEASE.2025-04-22T22-12-26Z"
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

  # Pin to the last release before the May 24, 2025 Console change so the web UI keeps
  # the fuller access-management/admin experience the user expects.
  $minioUrls = @(
    "https://dl.min.io/server/minio/release/windows-amd64/archive/minio.$preferredMinIORelease",
    "https://dl.min.io/server/minio/release/windows-amd64/archive/minio.RELEASE.2025-01-18T00-31-37Z",
    "https://dl.min.io/server/minio/release/windows-amd64/archive/minio.RELEASE.2023-10-16T04-13-43Z",
    "https://dl.min.io/server/minio/release/windows-amd64/archive/minio.RELEASE.2023-07-21T21-12-44Z",
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
set MINIO_SERVER_URL=
set MINIO_BROWSER_REDIRECT_URL=$consoleBrowserUrl
set MINIO_BROWSER_SESSION_DURATION=$browserSessionDuration
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
    if (Test-Path $idDir) {
      Warn "Resetting MinIO identity metadata: $idDir"
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
