@'
<#
Installs NetFix to Program Files and creates Desktop + Start Menu shortcuts.
Run as standard user; script self-elevates.
Files expected next to this script:
  - NetFix.exe
  - NetFix.ico
#>

# self-elevate
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[i] Requesting Administrator..."
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`""
    exit
}

$ScriptDir   = Split-Path -Parent $PSCommandPath
$InstallDir  = "$Env:ProgramFiles\NetFix"
$ExeSource   = Join-Path $ScriptDir "NetFix.exe"
$IconSource  = Join-Path $ScriptDir "NetFix.ico"
$ExeTarget   = Join-Path $InstallDir  "NetFix.exe"
$IconTarget  = Join-Path $InstallDir  "NetFix.ico"

$DesktopPath = [Environment]::GetFolderPath('Desktop')
$StartMenu   = Join-Path $Env:ProgramData "Microsoft\Windows\Start Menu\Programs"
$StartDir    = Join-Path $StartMenu "NetFix"
$LnkDesktop  = Join-Path $DesktopPath "NetFix.lnk"
$LnkStart    = Join-Path $StartDir   "NetFix.lnk"

Write-Host "[i] Installing to: $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Copy-Item $ExeSource  -Destination $ExeTarget  -Force
Copy-Item $IconSource -Destination $IconTarget -Force

New-Item -ItemType Directory -Force -Path $StartDir | Out-Null

function New-Shortcut {
    param(
        [Parameter(Mandatory=$true)] [string] $Target,
        [Parameter(Mandatory=$true)] [string] $ShortcutPath,
        [string] $IconLocation = $null,
        [string] $WorkingDir = $null,
        [string] $Arguments = $null
    )
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath   = $Target
    if ($Arguments) { $Shortcut.Arguments = $Arguments }
    $Shortcut.WorkingDirectory = $WorkingDir ? $WorkingDir : (Split-Path $Target)
    if ($IconLocation) { $Shortcut.IconLocation = $IconLocation }
    $Shortcut.Save()
}

Write-Host "[i] Creating Desktop shortcut..."
New-Shortcut -Target $ExeTarget -ShortcutPath $LnkDesktop -IconLocation $IconTarget

Write-Host "[i] Creating Start Menu shortcut..."
New-Shortcut -Target $ExeTarget -ShortcutPath $LnkStart -IconLocation $IconTarget

Write-Host "✅ NetFix install complete."
Write-Host "   - App: $ExeTarget"
Write-Host "   - Desktop shortcut: $LnkDesktop"
Write-Host "   - Start Menu: $LnkStart"
'@ | Out-File -Encoding UTF8 -FilePath .\installer\Install-NetFix.ps1
