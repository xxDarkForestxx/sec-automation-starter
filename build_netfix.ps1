# build_netfix.ps1
# Optional env vars (choose any or none):
#   $env:NETFIX_HMAC_SECRET_B64 = "<base64 of 32 raw bytes>"
#   $env:NETFIX_HMAC_SECRET_HEX = "<64 hex chars>"
#   $env:NETFIX_HMAC_SECRET_FILE = "path\to\32bytes.bin"
#   $env:NETFIX_SECRET_ID = "release-2025.11.06"  # if omitted, auto-generated

$ErrorActionPreference = "Stop"

# (Optional) venv/bootstrap
# python -m venv .venv
# .\.venv\Scripts\Activate.ps1
# python -m pip install --upgrade pip
# pip install pyinstaller

Write-Host "[build] Injecting secrets…" -ForegroundColor Cyan
python .\inject_secret.py .\net_fix.py

Write-Host "[build] Building EXE with PyInstaller…" -ForegroundColor Cyan
pyinstaller --noconfirm --onefile --name "NetFix_by_Antonio_Reyes" .\net_fix.py

Write-Host "`n[build] Done. EXE at: dist\NetFix_by_Antonio_Reyes.exe" -ForegroundColor Green
