param(
  [Parameter(Mandatory=$true)][string]$RepoRoot
)

# WatchTower independent audit live-run harness.
# Runs the existing Tier-0 runners + selftests, captures exit codes, success
# tokens, transcripts, and a git working-tree snapshot BEFORE and AFTER so the
# non-mutation claim can be checked empirically. Read-only w.r.t. source; only
# writes under proofs\audit_liverun\.

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

if(-not (Test-Path -LiteralPath $RepoRoot -PathType Container)){
  Write-Host "INVALID_REPO_ROOT: $RepoRoot"
  exit 2
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ts = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$OutDir = Join-Path $RepoRoot ("proofs\audit_liverun\" + $ts)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source

function GitPorcelain(){
  try {
    $o = & git -C $RepoRoot status --porcelain 2>$null
    return ($o | Out-String)
  } catch { return "GIT_UNAVAILABLE`n" }
}

$headBefore   = (& git -C $RepoRoot rev-parse HEAD 2>$null)
$statusBefore = GitPorcelain

$steps = @(
  @{ name="tier0_full_green";       script="scripts\_RUN_watchtower_tier0_full_green_v1.ps1";       token="FULL_GREEN_OK" },
  @{ name="live_state_full_green";  script="scripts\_RUN_watchtower_live_state_full_green_v1.ps1";  token="WATCHTOWER_LIVE_STATE_FULL_GREEN_OK" },
  @{ name="selftest_packet_verify"; script="scripts\_selftest_watchtower_packet_verify_v1.ps1";     token="WATCHTOWER_PACKET_VERIFY_SELFTEST_OK" },
  @{ name="selftest_state";         script="scripts\_selftest_watchtower_state_v1.ps1";             token="WATCHTOWER_STATE_SELFTEST_OK" },
  @{ name="selftest_device_chain";  script="scripts\_selftest_watchtower_device_chain_v1.ps1";      token="WATCHTOWER_DEVICE_CHAIN_SELFTEST_OK" },
  @{ name="selftest_device_binding";script="scripts\_selftest_watchtower_device_binding_v1.ps1";    token="WATCHTOWER_DEVICE_BINDING_SELFTEST_OK" },
  @{ name="selftest_pcv1";          script="scripts\_selftest_packet_constitution_v1.ps1";          token="" },
  @{ name="selftest_ingest_move";   script="scripts\_selftest_watchtower_ingest_move_pcv1_v1.ps1";  token="" },
  @{ name="selftest_cli";           script="scripts\_selftest_watchtower_cli_v1.ps1";               token="" }
)

$results = @()
foreach($s in $steps){
  $scriptPath = Join-Path $RepoRoot $s.script
  $outPath = Join-Path $OutDir ($s.name + ".stdout.txt")
  $errPath = Join-Path $OutDir ($s.name + ".stderr.txt")

  if(-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)){
    Write-Host ("MISSING  {0}  ({1})" -f $s.name, $s.script)
    $results += [pscustomobject]@{ step=$s.name; present=$false; exit=$null; token=$s.token; token_seen=$false; ok=$false }
    continue
  }

  $needsRepoRoot = [bool](Select-String -LiteralPath $scriptPath -Pattern 'RepoRoot' -Quiet)
  if($needsRepoRoot){
    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptPath -RepoRoot $RepoRoot 1> $outPath 2> $errPath
  } else {
    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptPath 1> $outPath 2> $errPath
  }
  $exit = $LASTEXITCODE

  $stdout = ""
  if(Test-Path -LiteralPath $outPath){ $stdout = (Get-Content -Raw -LiteralPath $outPath -ErrorAction SilentlyContinue) }
  if($null -eq $stdout){ $stdout = "" }

  $tokenSeen = $false
  if($s.token -ne "" -and $stdout -ne ""){ $tokenSeen = [bool]($stdout -match [Regex]::Escape($s.token)) }

  $ok = ($exit -eq 0) -and (($s.token -eq "") -or $tokenSeen)
  $tag = if($ok){"PASS"} else {"FAIL"}
  Write-Host ("{0,-8} {1,-26} exit={2} token_seen={3}" -f $tag, $s.name, $exit, $tokenSeen)
  $results += [pscustomobject]@{ step=$s.name; present=$true; exit=$exit; token=$s.token; token_seen=$tokenSeen; ok=$ok }
}

$headAfter   = (& git -C $RepoRoot rev-parse HEAD 2>$null)
$statusAfter = GitPorcelain

Set-Content -LiteralPath (Join-Path $OutDir "git_status_before.txt") -Value $statusBefore
Set-Content -LiteralPath (Join-Path $OutDir "git_status_after.txt")  -Value $statusAfter

# Which files changed during the run (mutation evidence). Excludes the audit dir itself.
$before = @($statusBefore -split "`n" | Where-Object { $_ -ne "" })
$after  = @($statusAfter  -split "`n" | Where-Object { $_ -ne "" -and $_ -notmatch 'audit_liverun' })
$mutated = @($after | Where-Object { $before -notcontains $_ })
Set-Content -LiteralPath (Join-Path $OutDir "mutated_during_run.txt") -Value ($mutated -join "`n")

$summary = [pscustomobject]@{
  schema        = "watchtower.audit_liverun.v1"
  generated_utc = $ts
  repo_root     = $RepoRoot
  ps_version    = $PSVersionTable.PSVersion.ToString()
  head_before   = $headBefore
  head_after    = $headAfter
  steps         = $results
  mutated_paths_during_run = $mutated
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutDir "SUMMARY.json")

Write-Host ""
Write-Host "==================================================="
Write-Host ("MUTATED FILES DURING RUN: " + $mutated.Count)
foreach($m in $mutated){ Write-Host ("   " + $m) }
Write-Host "OUTPUT_DIR: $OutDir"
Write-Host "WATCHTOWER_AUDIT_LIVERUN_DONE"
