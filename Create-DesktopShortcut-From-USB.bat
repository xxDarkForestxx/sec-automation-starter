@'
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Create-DesktopShortcut-From-USB.ps1"
pause
'@ | Out-File -Encoding ASCII -FilePath .\installer\Create-DesktopShortcut-From-USB.bat
