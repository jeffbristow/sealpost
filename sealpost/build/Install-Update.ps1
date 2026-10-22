# =====================================================================
#  Sealpost - Install-Update.ps1
#  Applies a Sealpost update to an EXISTING installation, no reinstall.
#
#  What it does:
#    1. Finds where Sealpost is installed (registry, then default folders,
#       then asks you).
#    2. Closes Sealpost if it is running.
#    3. Backs up the current app code (resources\app.asar -> app.asar.backup).
#    4. Copies the new code in and restarts Sealpost.
#
#  Your accounts, settings and PGP keys live in %APPDATA%\Sealpost and are
#  NOT touched.
#  To undo: delete resources\app.asar and rename app.asar.backup to app.asar.
# =====================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------- Section: locate the update file next to this script ----------
$update = Get-ChildItem -Path $here -Filter 'Sealpost-*.sealpost' | Sort-Object Name | Select-Object -Last 1
if (-not $update) { Write-Host 'No Sealpost-*.sealpost file found next to this script.' -ForegroundColor Red; exit 1 }
$newVersion = ($update.BaseName -replace '^Sealpost-', '')
Write-Host "Sealpost update $newVersion" -ForegroundColor Cyan

# ---------- Section: find the installation folder ----------
$candidates = @()
$uninstallRoots = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
$regKey = $null
foreach ($root in $uninstallRoots) {
  Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($p.DisplayName -like 'Sealpost*') {
      if ($p.InstallLocation) { $candidates += $p.InstallLocation.Trim('"') }
      if ($p.DisplayIcon) { $candidates += (Split-Path -Parent ($p.DisplayIcon.Split(',')[0].Trim('"'))) }
      if (-not $regKey) { $regKey = $_.PSPath }
    }
  }
}
$candidates += (Join-Path $env:LOCALAPPDATA 'Programs\sealpost')
$candidates += (Join-Path $env:LOCALAPPDATA 'Programs\Sealpost')
$candidates += (Join-Path $env:ProgramFiles 'Sealpost')

$install = $candidates | Where-Object { $_ -and (Test-Path (Join-Path $_ 'Sealpost.exe')) } | Select-Object -First 1
if (-not $install) {
  Write-Host 'Could not find Sealpost automatically.' -ForegroundColor Yellow
  $install = Read-Host 'Paste the folder that contains Sealpost.exe'
  $install = $install.Trim('"', ' ')
  if (-not (Test-Path (Join-Path $install 'Sealpost.exe'))) { Write-Host 'Sealpost.exe not found there.' -ForegroundColor Red; exit 1 }
}
$asar = Join-Path $install 'resources\app.asar'
Write-Host "Installed at: $install"

# ---------- Section: close Sealpost if running ----------
$procs = Get-Process -Name 'Sealpost' -ErrorAction SilentlyContinue
if ($procs) {
  Write-Host 'Closing Sealpost...'
  $procs | ForEach-Object { $_.CloseMainWindow() | Out-Null }
  Start-Sleep -Seconds 3
  Get-Process -Name 'Sealpost' -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 1
}

# ---------- Section: back up and replace (elevate only if needed) ----------
try {
  if (Test-Path $asar) { Copy-Item $asar "$asar.backup" -Force }
  Copy-Item $update.FullName $asar -Force
} catch {
  # usually 'access denied' (e.g. installed under Program Files)
  Write-Host "Could not write the update ($($_.Exception.Message)). Asking for administrator permission..." -ForegroundColor Yellow
  $cmd = "Copy-Item -LiteralPath '$asar' -Destination '$asar.backup' -Force -ErrorAction SilentlyContinue; Copy-Item -LiteralPath '$($update.FullName)' -Destination '$asar' -Force"
  Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmd
}

# verify the copy
if ((Get-FileHash $asar).Hash -ne (Get-FileHash $update.FullName).Hash) {
  Write-Host 'The update could not be written. Restoring your previous version - nothing has changed.' -ForegroundColor Red
  if (Test-Path "$asar.backup") { Copy-Item "$asar.backup" $asar -Force -ErrorAction SilentlyContinue }
  exit 1
}

# keep Windows "Installed apps" version number in sync (best effort)
if ($regKey) { try { Set-ItemProperty -Path $regKey -Name DisplayVersion -Value $newVersion } catch { } }

Write-Host "Sealpost updated to $newVersion." -ForegroundColor Green
Start-Process (Join-Path $install 'Sealpost.exe')
