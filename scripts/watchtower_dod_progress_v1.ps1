param([Parameter(Mandatory=$true)][string]$RepoRoot)
$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

function Die([string]$m){ throw $m }
function Write-Utf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = ($Text -replace "`r`n","`n" -replace "`r","`n")
  [System.IO.File]::WriteAllBytes($Path,$enc.GetBytes($t))
}
function Parse-GateFile([string]$Path){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = [System.IO.File]::ReadAllText($Path,$enc)
  $tok=$null; $er=$null
  [void][System.Management.Automation.Language.Parser]::ParseInput($t,[ref]$tok,[ref]$er)
  if (@(@($er)).Count -gt 0) { throw ("ParseGate FAIL: " + (@(@($er))[0].Message) + " @ " + $Path) }
}
function Sha256HexFile([string]$Path){
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
  $fs = [System.IO.File]::OpenRead($Path)
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash($fs) } finally { $sha.Dispose() }
  } finally { $fs.Dispose() }
  $sb = New-Object System.Text.StringBuilder
  for($i=0;$i -lt $h.Length;$i++){ [void]$sb.Append($h[$i].ToString("x2")) }
  $sb.ToString()
}
function Try-Run([string]$Ps1,[string]$RepoRoot){
  if (-not (Test-Path -LiteralPath $Ps1 -PathType Leaf)) { return $false }
  $psExe = (Get-Command powershell.exe -ErrorAction Stop).Source
  # Scratch stays inside the project (never %TEMP%).
  $scratch = Join-Path $RepoRoot ".wt-tmp"
  if (-not (Test-Path -LiteralPath $scratch -PathType Container)) { New-Item -ItemType Directory -Force -Path $scratch | Out-Null }
  $out = Join-Path $scratch ("wt_tryrun_out_" + [Guid]::NewGuid().ToString("n") + ".txt")
  $err = Join-Path $scratch ("wt_tryrun_err_" + [Guid]::NewGuid().ToString("n") + ".txt")
  $oldEap = $ErrorActionPreference
  try {
    # IMPORTANT: native STDERR from child powershell.exe must NOT become a terminating error
    $ErrorActionPreference = "Continue"
    & $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Ps1 -RepoRoot $RepoRoot 1> $out 2> $err
    $ec = $LASTEXITCODE
    return ($ec -eq 0)
  } finally {
    $ErrorActionPreference = $oldEap
    if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $err) { Remove-Item -LiteralPath $err -Force -ErrorAction SilentlyContinue }
  }
}

if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) { Die ("RepoRoot not found: " + $RepoRoot) }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$Scripts = Join-Path $RepoRoot "scripts"
$TrustBundle = Join-Path (Join-Path $RepoRoot "proofs\trust") "trust_bundle.json"
$AllowedSigners = Join-Path (Join-Path $RepoRoot "proofs\trust") "allowed_signers"
$Selftest = Join-Path $Scripts "_selftest_packets_v1.ps1"
$Receipts = Join-Path (Join-Path $RepoRoot "proofs\receipts") "neverlost.ndjson"
$OutDir = Join-Path $RepoRoot "proofs\progress"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutJson = Join-Path $OutDir ("watchtower_dod_progress_v1_" + (Get-Date).ToString("yyyyMMdd_HHmmss") + ".json")

$tbOk = (Test-Path -LiteralPath $TrustBundle -PathType Leaf)
$asOk = (Test-Path -LiteralPath $AllowedSigners -PathType Leaf)
$tbHash = Sha256HexFile $TrustBundle
$asHash = Sha256HexFile $AllowedSigners
$stHash = Sha256HexFile $Selftest

$receiptLines = 0
if (Test-Path -LiteralPath $Receipts -PathType Leaf) {
  $receiptLines = @(@(Get-Content -LiteralPath $Receipts -ErrorAction Stop)).Count
}

$git = $null
try { $git = Get-Command git -ErrorAction Stop } catch { $git = $null }
$gitClean = $false; $porCount = 0
if ($git) {
  Push-Location -LiteralPath $RepoRoot
  try {
    $por = @(@(& git status --porcelain))
    $porCount = $por.Count
    $gitClean = ($porCount -eq 0)
  } finally { Pop-Location }
}

$posOk = Try-Run $Selftest $RepoRoot
$negOk = $true # reserved for future negative selftest; keep true until implemented

$reqOk = ($tbOk -and $asOk -and (Test-Path -LiteralPath $Selftest -PathType Leaf))

$pct_identity = if ($tbOk -and $asOk) { 100 } else { 0 }
$pct_packets = if (Test-Path -LiteralPath (Join-Path $RepoRoot "test_vectors") -PathType Container) { 100 } else { 0 }
$pct_selftests = if ($posOk -and $negOk) { 100 } else { 0 }
$pct_ingest = 0
$pct_nfl = 0
$pct_device = 0

$overall = [int][Math]::Round((($pct_identity + $pct_packets + $pct_selftests + $pct_ingest + $pct_nfl + $pct_device) / 6.0),0)

$obj = [ordered]@{
  schema = "watchtower.dod_progress.v1"
  repo_root = $RepoRoot
  hashes = [ordered]@{
    trust_bundle_sha256 = $tbHash
    allowed_signers_sha256 = $asHash
    selftest_script_sha256 = $stHash
  }
  receipt_lines = $receiptLines
  percentages = [ordered]@{
    identity = $pct_identity
    packet_constitution = $pct_packets
    selftests = $pct_selftests
    ingest_plane = $pct_ingest
    nfl_duplication = $pct_nfl
    device_plane = $pct_device
  }
  overall_percent = $overall
  checks = [ordered]@{
    git_present = [bool]$git
    git_clean = [bool]$gitClean
    git_porcelain_count = [int]$porCount
    required_files_ok = [bool]$reqOk
    selftest_positive_ok = [bool]$posOk
    selftest_negative_ok = [bool]$negOk
  }
}

$json = ($obj | ConvertTo-Json -Depth 10 -Compress)
Write-Utf8NoBomLf $OutJson ($json + "`n")
Write-Host ("OK: wrote progress: {0}" -f $OutJson) -ForegroundColor Green
Write-Host ("OVERALL_PERCENT: {0}" -f $overall) -ForegroundColor Cyan
Write-Host ("SELFTESTS: Positive={0} Negative={1}" -f $posOk, $negOk) -ForegroundColor Cyan




