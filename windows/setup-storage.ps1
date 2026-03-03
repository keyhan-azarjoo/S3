$moduleRoot = Join-Path $PSScriptRoot "modules"
$moduleFiles = @("common.ps1","minio.ps1","cleanup.ps1","iis.ps1","docker.ps1","main.ps1")
$staleModuleFiles = @("common.ps1","minio.ps1","cleanup.ps1","iis.ps1","docker.ps1","main.ps1","core.ps1")
$remoteModuleBase = "https://raw.githubusercontent.com/keyhan-azarjoo/S3/main/windows/modules"

function Remove-StaleTempModules {
  if (-not (Test-Path $moduleRoot)) {
    return
  }

  foreach ($moduleFile in $staleModuleFiles) {
    $modulePath = Join-Path $moduleRoot $moduleFile
    if (-not (Test-Path $modulePath)) {
      continue
    }

    try {
      Remove-Item -Path $modulePath -Force -ErrorAction Stop
    } catch {
      Write-Host "[WARN] Could not remove stale module file: $modulePath" -ForegroundColor Yellow
    }
  }
}


function Initialize-ModuleRoot {
  $tempPath = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
  $scriptPath = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
  $refreshModules = $scriptPath.StartsWith($tempPath, [System.StringComparison]::OrdinalIgnoreCase)

  if (-not $refreshModules -and (Test-Path $moduleRoot) -and ($moduleFiles | ForEach-Object { Test-Path (Join-Path $moduleRoot $_) } | Where-Object { -not $_ }).Count -eq 0) {
    return
  }

  try {
    if (-not (Test-Path $moduleRoot)) {
      New-Item -ItemType Directory -Path $moduleRoot -Force | Out-Null
    }

    if ($refreshModules) {
      Remove-StaleTempModules
    }

    foreach ($moduleFile in $moduleFiles) {
      $modulePath = Join-Path $moduleRoot $moduleFile
      if ((-not $refreshModules) -and (Test-Path $modulePath)) {
        continue
      }

      $moduleUrl = "$remoteModuleBase/$moduleFile"
      $action = if (Test-Path $modulePath) { "Refreshing" } else { "Downloading missing" }
      Write-Host "[INFO] $action module: $moduleFile" -ForegroundColor Yellow
      Invoke-WebRequest -Uri $moduleUrl -OutFile $modulePath -UseBasicParsing
    }
  } catch {
    Write-Host "[ERROR] Failed to download required modules: $($_.Exception.Message)" -ForegroundColor Red
  }

  foreach ($moduleFile in $moduleFiles) {
    $modulePath = Join-Path $moduleRoot $moduleFile
    if (-not (Test-Path $modulePath)) {
      Write-Host "[ERROR] Missing required module: $modulePath" -ForegroundColor Red
      Write-Host "[ERROR] Keep the 'modules' folder next to setup-storage.ps1 or rerun with internet access." -ForegroundColor Red
      exit 1
    }
  }
}

Initialize-ModuleRoot

. (Join-Path $moduleRoot "common.ps1")
. (Join-Path $moduleRoot "minio.ps1")
. (Join-Path $moduleRoot "cleanup.ps1")
. (Join-Path $moduleRoot "iis.ps1")
. (Join-Path $moduleRoot "docker.ps1")
. (Join-Path $moduleRoot "main.ps1")

Invoke-LocalS3WindowsSetup
