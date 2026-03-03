function Invoke-LocalS3WindowsSetup {
  Relaunch-Elevated
  Initialize-NetworkDefaults
  Info "===== Local S3 Storage Installer (Windows) ====="

  $mode = Ask-InstallMode
  if ($mode -eq "iis") {
    Invoke-LocalS3IISSetup
    return
  }

  Invoke-LocalS3DockerSetup
}
