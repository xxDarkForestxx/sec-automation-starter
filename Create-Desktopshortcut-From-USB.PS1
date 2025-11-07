@'
<#
Creates a Desktop shortcut pointing to NetFix.exe on THIS drive.
Keep NetFix.exe and NetFix.ico next to this script on the USB.
#>
$Base = Split-Path -Parent $PSCommandPath
$Exe  = Join-Path $Base "NetFix.exe"
$Ico  = Join-Path $Base "NetFix.ico"

if (-not (Test-Path $Exe)) { Write-Host "[!] NetFix.exe not found next to this script." ; exit 1 }
if (-not (Test-Path $Ico)) { Write-Host "[!] NetFix.ico not found next to this script." ; exit 1 }

$Desktop = [Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "NetFix (USB).lnk"

$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $Exe
$Shortcut.WorkingDirectory = (Split-Path $Exe)
$Shortcut.IconLocation = $Ico
$Shortcut.Save()

Write-Host "✅ Desktop shortcut created -> $ShortcutPath"
'@ | Out-File -Encoding UTF8 -FilePath .\installer\Create-DesktopShortcut-From-USB.ps1
