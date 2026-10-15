@echo off
setlocal
rem WatchTower release gate on this Windows host (closes DoD v2 D14/D15 evidence when run here).
rem Runs every suite under Windows PowerShell 5.1, then under PowerShell 7 when installed.
rem Sibling checkouts (..\cpr, ..\neverlost, ..\arbiter, ..\..\_Atlas-Systems\live-state-surgeon)
rem are used for interop when present. Reports go to .scratch\ (git-ignored).
set "HERE=%~dp0"
if not exist "%HERE%.scratch" mkdir "%HERE%.scratch"
echo === Windows PowerShell 5.1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%scripts\_RUN_watchtower_canonical_full_green_v2.ps1" -Scope all -ReportPath "%HERE%.scratch\tier0_ps51.json"
where pwsh >nul 2>nul
if %ERRORLEVEL%==0 (
  echo.
  echo === PowerShell 7
  pwsh -NoProfile -File "%HERE%scripts\_RUN_watchtower_canonical_full_green_v2.ps1" -Scope all -ReportPath "%HERE%.scratch\tier0_pwsh7.json"
)
echo.
echo Reports: %HERE%.scratch\tier0_*.json
pause
