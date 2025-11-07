@echo off
setlocal enabledelayedexpansion

REM Optional env vars (choose any or none)
REM set NETFIX_HMAC_SECRET_B64=...
REM set NETFIX_HMAC_SECRET_HEX=...
REM set NETFIX_HMAC_SECRET_FILE=path\to\32bytes.bin
REM set NETFIX_SECRET_ID=release-2025.11.06

echo [build] Injecting secrets...
python inject_secret.py net_fix.py || goto :error

echo [build] Building EXE with PyInstaller...
pyinstaller --noconfirm --onefile --name "NetFix_by_Antonio_Reyes" net_fix.py || goto :error

echo.
echo [build] Done. EXE at: dist\NetFix_by_Antonio_Reyes.exe
goto :eof

:error
echo Build failed.
exit /b 1
