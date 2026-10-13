@echo off
setlocal
set "HERE=%~dp0"
echo Applying WatchTower audit hygiene fixes in "%HERE:~0,-1%"
echo Nothing will be pushed. All changes land on a local branch.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%scripts\_APPLY_audit_fixes_v1.ps1" -RepoRoot "%HERE:~0,-1%"
echo.
echo ================================================================
echo Done. Review with: git log  and  git status
echo You can close this window (or press any key).
pause >nul
