$localWindowsScript = Join-Path $PSScriptRoot "windows\setup-storage.ps1"
$remoteWindowsScript = "https://raw.githubusercontent.com/keyhan-azarjoo/S3/main/windows/setup-storage.ps1"
$downloadedWindowsScript = Join-Path $PSScriptRoot "windows-setup-storage.ps1"

if (Test-Path $localWindowsScript) {
  & $localWindowsScript
  exit $LASTEXITCODE
}

Invoke-WebRequest -Uri $remoteWindowsScript -OutFile $downloadedWindowsScript -UseBasicParsing
& $downloadedWindowsScript
exit $LASTEXITCODE
