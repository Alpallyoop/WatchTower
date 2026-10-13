param(
  [string]$RepoRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

# WatchTower audit hygiene fixes — native applier.
# Runs on Windows (fast, full rights) instead of the slow bridge mount.
# Reversible: works on a branch, makes separate commits, pushes NOTHING.
# Author: audit 2026-08-26. See docs/WATCHTOWER_WBS_OFFICIAL_v1.md sections 4 / 4a.

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $RepoRoot
Write-Host "REPO: $RepoRoot"

git rev-parse --is-inside-work-tree *> $null
if($LASTEXITCODE -ne 0){ Write-Host "NOT_A_GIT_REPO"; exit 2 }

function Commit([string]$msg){
  git commit -q -m $msg
  if($LASTEXITCODE -ne 0){ Write-Host "   (nothing to commit for: $msg)" }
  else { Write-Host "   committed: $msg" }
}

# --- 0. clear any stale index locks from prior crashed processes ---
Get-ChildItem -LiteralPath ".git" -Filter "index.lock*" -Force -ErrorAction SilentlyContinue |
  Remove-Item -Force -ErrorAction SilentlyContinue

# --- 1. ensure we are on the audit branch, clean index ---
$branch = "audit/hygiene-fixes-20260826"
git checkout -B $branch *> $null
git reset -q
Write-Host "BRANCH: $branch"

# --- Commit 1: official docs ---
git add -- docs/WATCHTOWER_WBS_OFFICIAL_v1.md docs/WATCHTOWER_DOD_OFFICIAL_v1.md
Commit "docs: add official WBS + DoD audit documents (evidence-based)"

# --- Commit 2: gitignore ---
git add -- .gitignore
Commit "chore(gitignore): ignore node_modules and UI build info"

# --- Commit 3: untrack committed node_modules (kept on disk) ---
if((git ls-files ui/node_modules | Measure-Object).Count -gt 0){
  git rm -r --cached --quiet -- ui/node_modules
}
Commit "chore: untrack committed ui/node_modules (kept on disk)"

# --- Commit 4: repoint CLI selftest to the real command surface ---
git add -- scripts/_selftest_watchtower_cli_v1.ps1
Commit "fix(cli): repoint CLI selftest to real commands (quick-check/version/doctor + fail-closed negative)"

# --- Commit 5: hygiene removals ---
Write-Host "Applying hygiene removals..."

# 5a. dead / duplicate UI sources (unreferenced; main.tsx + App.tsx use src/workbench/*)
Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath "ui/src/watchtower_ui_workbench_shell.tsx"
Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath "ui/src/workbench/watchtower_ui_workbench_shell.tsx.bak_v21a_20260531_223210"
Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath "ui/src/lib/watchtower_api.ts"
if((Test-Path "ui/src/lib") -and -not (Get-ChildItem "ui/src/lib" -Force)){ Remove-Item -Force "ui/src/lib" }

# 5b. corrupt directory created by a botched PowerShell redirect
Get-ChildItem -Force -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -like "k in *Map.Keys*" } |
  ForEach-Object { Write-Host ("   removing corrupt dir: " + $_.Name); Remove-Item -Recurse -Force -LiteralPath $_.FullName }

# 5c. stray empty top-level workbench (real one is ui/workbench)
if(Test-Path "workbench"){
  $wbReal = Get-ChildItem "workbench" -Force -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notlike "*.json" -and $_.FullName -notlike "*node_modules*" }
  if(-not $wbReal){ Write-Host "   removing stray top-level workbench/"; Remove-Item -Recurse -Force "workbench" }
  else { Write-Host "   KEEPING workbench/ (unexpected real files found) — review manually" }
}

# 5d. retire compromised / passphrase private keys — MOVE (reversible), do not destroy
$retired = "proofs/keys/_RETIRED_MOVE_OFFLINE_OR_DESTROY"
$badKeys = Get-ChildItem "proofs/keys" -File -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -match "COMPROMISED|PASSPHRASE" }
if($badKeys){
  New-Item -ItemType Directory -Force -Path $retired | Out-Null
  foreach($k in $badKeys){ Write-Host ("   retiring key: " + $k.Name); Move-Item -Force -LiteralPath $k.FullName -Destination (Join-Path $retired $k.Name) }
  Write-Host "   >>> ACTION: these are private keys. Move $retired OFFLINE or destroy it. Never re-trust them."
}

# 5e. prune trust backups (already gitignored; disk clutter only)
Get-ChildItem "proofs/trust" -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match "\.bak_" } |
  ForEach-Object { Remove-Item -Force -LiteralPath $_.FullName }

# stage tracked deletions (only ui/src dup shell is tracked; the rest are untracked/ignored)
git add -A -- ui/src
Commit "chore: remove dead UI dup sources; retire compromised keys; prune trust backups; drop corrupt dir + stray workbench"

Write-Host ""
Write-Host "=================== RESULT ==================="
git log --oneline -6
Write-Host ""
Write-Host "Branch '$branch' — nothing was pushed. Review with: git log; git show <hash>"
Write-Host "To re-verify the CLI fix + substrate, re-run RUN_AUDIT_LIVERUN.bat"
Write-Host "WATCHTOWER_AUDIT_FIXES_APPLIED_OK"
