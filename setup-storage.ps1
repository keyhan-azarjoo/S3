$localWindowsScript = Join-Path $PSScriptRoot "windows\setup-storage.ps1"
$remoteWindowsScript = "https://raw.githubusercontent.com/keyhan-azarjoo/S3/main/windows/setup-storage.ps1"
$downloadedWindowsScript = Join-Path $PSScriptRoot "windows-setup-storage.ps1"
$downloadedModuleRoot = Join-Path $PSScriptRoot "modules"

if (Test-Path $localWindowsScript) {
  & $localWindowsScript
  exit $LASTEXITCODE
}

if (Test-Path $downloadedWindowsScript) {
  Remove-Item -Path $downloadedWindowsScript -Force -ErrorAction SilentlyContinue
}

if (Test-Path $downloadedModuleRoot) {
  Remove-Item -Recurse -Force -Path $downloadedModuleRoot -ErrorAction SilentlyContinue
}

Invoke-WebRequest -Uri $remoteWindowsScript -OutFile $downloadedWindowsScript -UseBasicParsing
& $downloadedWindowsScript
exit $LASTEXITCODE
