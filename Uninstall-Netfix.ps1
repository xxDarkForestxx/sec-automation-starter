@'
# self-elevate
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`""
    exit
}

$InstallDir = "$Env:ProgramFiles\NetFix"
$Desktop    = [Environment]::GetFolderPath('Desktop')
$StartMenu  = Join-Path $Env:ProgramData "Microsoft\Windows\Start Menu\Programs\NetFix"

$LnkDesktop = Join-Path $Desktop "NetFix.lnk"
$LnkStart   = Join-Path $StartMenu "NetFix.lnk"
Remove-Item $LnkDesktop -ErrorAction SilentlyContinue
Remove-Item $LnkStart   -ErrorAction SilentlyContinue
Remove-Item $StartMenu  -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item $InstallDir -Force -Recurse -ErrorAction SilentlyContinue

Write-Host "✅ NetFix uninstalled."
'@ | Out-File -Encoding UTF8 -FilePath .\installer\Uninstall-NetFix.ps1
