$moduleRoot = Join-Path $PSScriptRoot "modules"
$moduleFiles = @("common.ps1","minio.ps1","cleanup.ps1","iis.ps1","docker.ps1","main.ps1")

foreach ($moduleFile in $moduleFiles) {
  $modulePath = Join-Path $moduleRoot $moduleFile
  if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] Missing required module: $modulePath" -ForegroundColor Red
    Write-Host "[ERROR] This runner now uses local files only. Keep the 'modules' folder next to setup-storage.ps1." -ForegroundColor Red
    exit 1
  }
}

. (Join-Path $moduleRoot "common.ps1")
. (Join-Path $moduleRoot "minio.ps1")
. (Join-Path $moduleRoot "cleanup.ps1")
. (Join-Path $moduleRoot "iis.ps1")
. (Join-Path $moduleRoot "docker.ps1")
. (Join-Path $moduleRoot "main.ps1")

Invoke-LocalS3WindowsSetup
