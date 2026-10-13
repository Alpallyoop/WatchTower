@echo off
setlocal
set "HERE=%~dp0"
echo Running WatchTower audit live-run against "%HERE:~0,-1%"
echo This may take a minute. Do not close this window.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%scripts\_AUDIT_liverun_v1.ps1" -RepoRoot "%HERE:~0,-1%"
echo.
echo ================================================================
echo Audit run finished. Results are under proofs\audit_liverun\
echo You can close this window (or press any key).
pause >nul
