param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$HandoffDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$m){ throw ("WATCHTOWER_CONSUME_NFL_FAIL: " + $m) }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ return }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function Utf8NoBom(){ New-Object System.Text.UTF8Encoding($false) }
function NormalizeLf([string]$t){ if($null -eq $t){ return "" }; $u = ($t -replace "`r`n","`n") -replace "`r","`n"; if(-not $u.EndsWith("`n")){ $u += "`n" }; return $u }
function ReadUtf8([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Fail ("READ_MISSING: " + $Path) }; [System.IO.File]::ReadAllText($Path,(Utf8NoBom)) }
function WriteUtf8NoBomLfText([string]$Path,[string]$Text){ $dir = Split-Path -Parent $Path; if($dir){ EnsureDir $dir }; $u = NormalizeLf $Text; [System.IO.File]::WriteAllBytes($Path,(Utf8NoBom).GetBytes($u)); if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Fail ("WRITE_FAILED: " + $Path) } }
function Sha256Hex([string]$Path){ (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

function VerifySha256Sums([string]$Root,[string]$SumsPath){
  if(-not (Test-Path -LiteralPath $SumsPath -PathType Leaf)){ Fail ("MISSING_SHA256SUMS: " + $SumsPath) }
  $txt = NormalizeLf (ReadUtf8 $SumsPath)
  $lines = @($txt -split "`n")
  $count = 0
  foreach($line in $lines){
    if([string]::IsNullOrWhiteSpace($line)){ continue }
    if($line -notmatch '^[0-9a-fA-F]{64}  (.+)$'){ Fail ("BAD_SHA256SUM_LINE: " + $line) }
    $expected = $line.Substring(0,64).ToLowerInvariant()
    $rel = [string]$Matches[1]
    $full = Join-Path $Root $rel
    if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ Fail ("MISSING_TARGET: " + $rel) }
    $actual = Sha256Hex $full
    if($actual -ne $expected){ Fail ("SHA256_MISMATCH: " + $rel + " expected=" + $expected + " actual=" + $actual) }
    $count++
  }
  return $count
}

# Constellation integration receipt (proposal 0013): this legacy consumer is the only code path of
# the registered integration watchtower > nfl (contract nfl.tier0.selftest.v1), so every run writes
# one constellation.integration.receipt.v1 through the v2 module, failed runs included.
$script:WtModule = Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/WatchTower/WatchTower.psd1') -Force -PassThru
$script:HandoffResponseSha = ''
function Write-HandoffIntegrationReceipt([string]$Outcome,[string]$Token){
  & $script:WtModule {
    param($root,$response,$outcome,$token)
    $receipt = New-WtIntegrationReceipt -Provider 'nfl' -Contract 'nfl.tier0.selftest.v1' -RequestSha256 '' -ResponseSha256 $response -Outcome $outcome -ErrorToken $token
    [void](Add-WtIntegrationReceipt -Layout (Get-WtLayout $root) -Receipt $receipt)
  } $RepoRoot $script:HandoffResponseSha $Outcome $Token
}
trap {
  $m = [string]$_.Exception.Message
  $code = 'NFL_HANDOFF_FAILED'
  if($m -cmatch 'WATCHTOWER_CONSUME_NFL_FAIL: ([A-Z][A-Z0-9_]*)'){ $code = 'NFL_HANDOFF_' + $Matches[1] }
  $outcome = 'failed'
  if($code -eq 'NFL_HANDOFF_MISSING_MANIFEST' -or $code -eq 'NFL_HANDOFF_READ_MISSING'){ $outcome = 'unavailable' }
  try { Write-HandoffIntegrationReceipt $outcome $code } catch { Write-Output ('INTEGRATION_RECEIPT_WRITE_FAILED: ' + $_.Exception.Message) }
  break
}

$RepoRoot   = (Resolve-Path -LiteralPath $RepoRoot).Path
if(-not (Test-Path -LiteralPath $HandoffDir -PathType Container)){ Fail ("MISSING_MANIFEST: handoff directory " + $HandoffDir) }
$HandoffDir = (Resolve-Path -LiteralPath $HandoffDir).Path
$ProofsDir  = Join-Path $RepoRoot "proofs"
$RcptDir    = Join-Path $ProofsDir "receipts"
EnsureDir $ProofsDir
EnsureDir $RcptDir

$ManifestPath = Join-Path $HandoffDir "WATCHTOWER_HANDOFF_MANIFEST.json"
$SumsPath     = Join-Path $HandoffDir "sha256sums.txt"
$FrozenDir    = Join-Path $HandoffDir "frozen"

if(-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)){ Fail ("MISSING_MANIFEST: " + $ManifestPath) }
$script:HandoffResponseSha = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if(-not (Test-Path -LiteralPath $SumsPath -PathType Leaf)){ Fail ("MISSING_HANDOFF_SUMS: " + $SumsPath) }
if(-not (Test-Path -LiteralPath $FrozenDir -PathType Container)){ Fail ("MISSING_FROZEN_DIR: " + $FrozenDir) }

$sumCount = VerifySha256Sums $HandoffDir $SumsPath
Write-Output ("HANDOFF_SHA256SUMS_OK entries=" + $sumCount)

$manifestTxt = ReadUtf8 $ManifestPath
$manifest = $manifestTxt | ConvertFrom-Json -ErrorAction Stop
if(-not $manifest){ Fail "MANIFEST_PARSE_EMPTY" }

if([string]$manifest.schema -ne "watchtower.handoff.manifest.v1"){ Fail "BAD_MANIFEST_SCHEMA" }
if([string]$manifest.source_instrument -ne "NFL"){ Fail "BAD_SOURCE_INSTRUMENT" }
if([string]$manifest.source_role -ne "witness-only"){ Fail "BAD_SOURCE_ROLE" }

$reqFrozen = @(
  (Join-Path $FrozenDir "nfl.tier0.selftest.v1.ndjson"),
  (Join-Path $FrozenDir "selftest_verify_packet.stdout.txt"),
  (Join-Path $FrozenDir "selftest_verify_packet.stderr.txt"),
  (Join-Path $FrozenDir "selftest_vectors.stdout.txt"),
  (Join-Path $FrozenDir "selftest_vectors.stderr.txt"),
  (Join-Path $FrozenDir "sha256sums.txt")
)
foreach($p in $reqFrozen){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Fail ("FROZEN_REQUIRED_MISSING: " + $p) }
}

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$receiptPath = Join-Path $RcptDir "watchtower.consume.nfl_handoff.v1.ndjson"
$obj = [ordered]@{
  schema = "watchtower.consume.nfl_handoff.v1"
  utc = $stamp
  ok = $true
  handoff_dir = $HandoffDir
  manifest_path = $ManifestPath
  sums_path = $SumsPath
  source_instrument = [string]$manifest.source_instrument
  source_role = [string]$manifest.source_role
  release_tag = [string]$manifest.release_tag
  verified_entries = [int]$sumCount
}
# The integration receipt is written before the legacy receipt (proposal 0013: locally first).
Write-HandoffIntegrationReceipt 'ok' ''
$line = ($obj | ConvertTo-Json -Compress)
WriteUtf8NoBomLfText $receiptPath ($line + "`n")

Write-Output "WATCHTOWER_CONSUME_NFL_OK"
Write-Output ("RECEIPT_APPEND_OK: " + $receiptPath)
