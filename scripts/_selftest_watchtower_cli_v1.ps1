param(
  [Parameter(Mandatory=$true)][string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# WatchTower CLI selftest.
# Repointed by audit (2026-08-26) from a never-implemented command surface
# (`device list`, `receipts list`, `freeze show`) to the CLI's REAL implemented
# commands, plus a fail-closed negative case. See docs/history/WATCHTOWER_WBS_OFFICIAL_v1.md (H9).

function WT-Die([string]$m){
  throw ("WATCHTOWER_CLI_SELFTEST_FAIL: " + $m)
}

function WT-InvokeCapture([string]$Script,[string[]]$ChildArgs){
  $PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source
  # Scratch stays inside the project (never %TEMP%).
  $scratch = Join-Path $RepoRoot ".wt-tmp"
  if(-not (Test-Path -LiteralPath $scratch -PathType Container)){ New-Item -ItemType Directory -Force -Path $scratch | Out-Null }
  $outFile = Join-Path $scratch ("watchtower_cli_selftest_" + [guid]::NewGuid().ToString("N") + ".txt")
  try {
    $p = Start-Process `
      -FilePath $PSExe `
      -ArgumentList (@("-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",$Script) + $ChildArgs) `
      -RedirectStandardOutput $outFile `
      -Wait `
      -PassThru `
      -NoNewWindow

    $txt = ""
    if(Test-Path -LiteralPath $outFile -PathType Leaf){
      $txt = [System.IO.File]::ReadAllText($outFile,[System.Text.Encoding]::UTF8)
      $txt = ($txt -replace "`r`n","`n") -replace "`r","`n"
    }

    return [pscustomobject]@{
      ExitCode = $p.ExitCode
      Output   = $txt
    }
  }
  finally {
    if(Test-Path -LiteralPath $outFile -PathType Leaf){
      Remove-Item -LiteralPath $outFile -Force
    }
  }
}

if(-not (Test-Path -LiteralPath $RepoRoot -PathType Container)){
  WT-Die ("INVALID_REPO_ROOT: " + $RepoRoot)
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$Cli = Join-Path $RepoRoot "scripts\watchtower_cli_v1.ps1"
if(-not (Test-Path -LiteralPath $Cli -PathType Leaf)){
  WT-Die ("CLI_MISSING: " + $Cli)
}

# --- Positive cases: real, implemented, engine-independent commands ---

$r = WT-InvokeCapture $Cli @("-RepoRoot",$RepoRoot,"quick-check")
if($r.ExitCode -ne 0){ WT-Die ("QUICK_CHECK_EXIT_" + $r.ExitCode + ": " + $r.Output) }
if($r.Output -notmatch 'WATCHTOWER_QUICK_CHECK_OK'){ WT-Die "QUICK_CHECK_TOKEN_MISSING" }
Write-Host "CASE_OK: quick_check" -ForegroundColor Green

$r = WT-InvokeCapture $Cli @("-RepoRoot",$RepoRoot,"version")
if($r.ExitCode -ne 0){ WT-Die ("VERSION_EXIT_" + $r.ExitCode + ": " + $r.Output) }
if($r.Output -notmatch 'WATCHTOWER_VERSION_OK'){ WT-Die "VERSION_TOKEN_MISSING" }
Write-Host "CASE_OK: version" -ForegroundColor Green

$r = WT-InvokeCapture $Cli @("-RepoRoot",$RepoRoot,"doctor")
if($r.ExitCode -ne 0){ WT-Die ("DOCTOR_EXIT_" + $r.ExitCode + ": " + $r.Output) }
if($r.Output -notmatch 'WATCHTOWER_DOCTOR_OK'){ WT-Die "DOCTOR_TOKEN_MISSING" }
Write-Host "CASE_OK: doctor" -ForegroundColor Green

# --- Negative case: an unknown command MUST fail closed (non-zero exit) ---

$r = WT-InvokeCapture $Cli @("-RepoRoot",$RepoRoot,"this-command-does-not-exist")
if($r.ExitCode -eq 0){ WT-Die "UNKNOWN_COMMAND_DID_NOT_FAIL_CLOSED" }
Write-Host "CASE_OK: unknown_command_fails_closed" -ForegroundColor Green

Write-Host "WATCHTOWER_CLI_SELFTEST_OK" -ForegroundColor Green
