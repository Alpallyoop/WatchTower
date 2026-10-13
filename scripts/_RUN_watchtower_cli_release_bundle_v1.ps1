param(
  [Parameter(Mandatory=$true)][string]$RepoRoot
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function WT-Die([string]$m){
  throw ("WATCHTOWER_CLI_RELEASE_BUNDLE_FAIL: " + $m)
}

function WT-EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ return }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WT-WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ WT-EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$t,$enc)
}

function WT-AppendUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ WT-EnsureDir $dir }
  [System.IO.File]::AppendAllText($Path,$t,$enc)
}

function WT-Sha256HexFile([string]$Path){
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $fs = [System.IO.File]::OpenRead($Path)
    try {
      return (($sha.ComputeHash($fs) | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
      $fs.Dispose()
    }
  }
  finally {
    $sha.Dispose()
  }
}

function WT-CopyFile([string]$Source,[string]$Dest){
  if(-not (Test-Path -LiteralPath $Source -PathType Leaf)){
    WT-Die ("SOURCE_MISSING: " + $Source)
  }
  $dir = Split-Path -Parent $Dest
  if($dir){ WT-EnsureDir $dir }
  Copy-Item -LiteralPath $Source -Destination $Dest -Force
}

if(-not (Test-Path -LiteralPath $RepoRoot -PathType Container)){
  WT-Die ("INVALID_REPO_ROOT: " + $RepoRoot)
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$ScriptsRoot = Join-Path $RepoRoot "scripts"
$FreezeRoot  = Join-Path $RepoRoot "proofs\freeze\watchtower_cli_v1"

$CliScript    = Join-Path $ScriptsRoot "watchtower_cli_v1.ps1"
$EngineScript = Join-Path $ScriptsRoot "watchtower_engine_v1.ps1"
$Selftest     = Join-Path $ScriptsRoot "_selftest_watchtower_cli_v1.ps1"
$FreezeRun    = Join-Path $ScriptsRoot "_RUN_watchtower_cli_freeze_v1.ps1"

$FreezeStdout = Join-Path $FreezeRoot "stdout.txt"
$FreezeStderr = Join-Path $FreezeRoot "stderr.txt"
$FreezeSha    = Join-Path $FreezeRoot "sha256sums.txt"

foreach($p in @($CliScript,$EngineScript,$Selftest,$FreezeRun,$FreezeStdout,$FreezeStderr,$FreezeSha)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    WT-Die ("REQUIRED_ARTIFACT_MISSING: " + $p)
  }
}

$ReleaseRoot = Join-Path $RepoRoot "release\watchtower_cli_v1"
if(Test-Path -LiteralPath $ReleaseRoot -PathType Container){
  Remove-Item -LiteralPath $ReleaseRoot -Recurse -Force
}
WT-EnsureDir $ReleaseRoot

$BundleScripts = Join-Path $ReleaseRoot "scripts"
$BundleProofs  = Join-Path $ReleaseRoot "proofs\freeze\watchtower_cli_v1"
$BundleDocs    = Join-Path $ReleaseRoot "docs"

WT-EnsureDir $BundleScripts
WT-EnsureDir $BundleProofs
WT-EnsureDir $BundleDocs

WT-CopyFile $CliScript    (Join-Path $BundleScripts "watchtower_cli_v1.ps1")
WT-CopyFile $EngineScript (Join-Path $BundleScripts "watchtower_engine_v1.ps1")
WT-CopyFile $Selftest     (Join-Path $BundleScripts "_selftest_watchtower_cli_v1.ps1")
WT-CopyFile $FreezeRun    (Join-Path $BundleScripts "_RUN_watchtower_cli_freeze_v1.ps1")

WT-CopyFile $FreezeStdout (Join-Path $BundleProofs "stdout.txt")
WT-CopyFile $FreezeStderr (Join-Path $BundleProofs "stderr.txt")
WT-CopyFile $FreezeSha    (Join-Path $BundleProofs "sha256sums.txt")

$ReadmePath = Join-Path $BundleDocs "README_watchtower_cli_v1.md"
$Readme = @"
# WatchTower CLI v1

Deterministic observer and evidence surface for WatchTower.

## Included
- scripts/watchtower_cli_v1.ps1
- scripts/watchtower_engine_v1.ps1
- scripts/_selftest_watchtower_cli_v1.ps1
- scripts/_RUN_watchtower_cli_freeze_v1.ps1
- proofs/freeze/watchtower_cli_v1/stdout.txt
- proofs/freeze/watchtower_cli_v1/stderr.txt
- proofs/freeze/watchtower_cli_v1/sha256sums.txt

## Example usage
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . version
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . quick-check
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . engine init
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . engine observe-device
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\watchtower_cli_v1.ps1 -RepoRoot . engine summary
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\_selftest_watchtower_cli_v1.ps1 -RepoRoot .

## Success tokens
- WATCHTOWER_VERSION_OK
- WATCHTOWER_QUICK_CHECK_OK
- WATCHTOWER_DOCTOR_OK
- WATCHTOWER_STATUS_OK
- WATCHTOWER_RECEIPTS_SUMMARY_OK
- WATCHTOWER_ENGINE_INIT_OK
- WATCHTOWER_ENGINE_DEVICE_OBSERVE_OK
- WATCHTOWER_ENGINE_TELEMETRY_OBSERVE_OK
- WATCHTOWER_ENGINE_SUMMARY_OK
- WATCHTOWER_CLI_SELFTEST_OK
- WATCHTOWER_CLI_FREEZE_OK
"@
WT-WriteUtf8NoBomLf -Path $ReadmePath -Text $Readme

$BundleSha = Join-Path $ReleaseRoot "sha256sums.txt"
$files = Get-ChildItem -LiteralPath $ReleaseRoot -Recurse -File | Sort-Object FullName
$shaLines = @()
foreach($f in $files){
  if($f.FullName -eq $BundleSha){ continue }
  $rel = $f.FullName.Substring($ReleaseRoot.Length).TrimStart('\') -replace '\\','/'
  $sha = WT-Sha256HexFile $f.FullName
  $shaLines += ($sha + "  " + $rel)
}
[System.IO.File]::WriteAllLines($BundleSha,$shaLines,(New-Object System.Text.UTF8Encoding($false)))

$ZipPath = Join-Path $RepoRoot "release\watchtower_cli_v1.zip"
if(Test-Path -LiteralPath $ZipPath -PathType Leaf){
  Remove-Item -LiteralPath $ZipPath -Force
}
Compress-Archive -Path (Join-Path $ReleaseRoot "*") -DestinationPath $ZipPath -CompressionLevel Optimal

$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\watchtower_cli_release_bundle.ndjson"
$utc = [DateTime]::UtcNow.ToString("o")
$zipSha = WT-Sha256HexFile $ZipPath
$receipt = '{"schema":"watchtower.cli.release.bundle.receipt.v1","utc":"' + $utc + '","release_root":"' + $ReleaseRoot.Replace('\','\\') + '","zip_path":"' + $ZipPath.Replace('\','\\') + '","zip_sha256":"' + $zipSha + '","status":"ok"}'
WT-AppendUtf8NoBomLf -Path $ReceiptPath -Text $receipt

Write-Host "WATCHTOWER_CLI_RELEASE_BUNDLE_OK" -ForegroundColor Green
Write-Host ("RELEASE_ROOT: " + $ReleaseRoot) -ForegroundColor Green
Write-Host ("ZIP: " + $ZipPath) -ForegroundColor Green
Write-Host ("ZIP_SHA256: " + $zipSha) -ForegroundColor Green
Write-Host ("RECEIPT: " + $ReceiptPath) -ForegroundColor Green