param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  # Default: the sibling NFL checkout next to this repository (was a fixed folder on C:).
  [Parameter(Mandatory=$false)][string]$HandoffDir = ""
)
if([string]::IsNullOrWhiteSpace($HandoffDir)){
  $HandoffDir = Join-Path (Split-Path -Parent $RepoRoot) "nfl\handoff\watchtower\nfl_tier0_watchtower_handoff_20260308T024440Z"
}

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$m){ throw ("WATCHTOWER_SELFTEST_NFL_HANDOFF_FAIL: " + $m) }

function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ return }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}
function Utf8NoBom(){ New-Object System.Text.UTF8Encoding($false) }
function NormalizeLf([string]$t){
  if($null -eq $t){ return "" }
  $u = ($t -replace "`r`n","`n") -replace "`r","`n"
  if(-not $u.EndsWith("`n")){ $u += "`n" }
  return $u
}
function ReadUtf8([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Fail ("READ_MISSING: " + $Path) }
  [System.IO.File]::ReadAllText($Path,(Utf8NoBom))
}
function WriteUtf8NoBomLfText([string]$Path,[string]$Text){
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  $u = NormalizeLf $Text
  [System.IO.File]::WriteAllBytes($Path,(Utf8NoBom).GetBytes($u))
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Fail ("WRITE_FAILED: " + $Path) }
}
function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Fail ("PARSEGATE_MISSING: " + $Path) }
  $tok=$null
  $err=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)
  if($err -and @(@($err)).Count -gt 0){
    $m = ($err | Select-Object -First 12 | ForEach-Object { $_.ToString() }) -join " | "
    Fail ("PARSEGATE_FAIL: " + $Path + " :: " + $m)
  }
}
function Sha256Hex([string]$Path){
  (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function RelPath([string]$Root,[string]$Full){
  $bs=[char]92
  $r=(Resolve-Path -LiteralPath $Root).Path.TrimEnd($bs)
  $f=(Resolve-Path -LiteralPath $Full).Path
  if($f.Length -lt $r.Length){ return $f.Replace($bs,[char]47) }
  if($f.Substring(0,$r.Length).ToLowerInvariant() -ne $r.ToLowerInvariant()){ return $f.Replace($bs,[char]47) }
  $rel=$f.Substring($r.Length).TrimStart($bs)
  return $rel.Replace($bs,[char]47)
}
function WriteSha256Sums([string]$Root,[string]$OutPath,[string[]]$FilesAbs){
  $rows = New-Object System.Collections.Generic.List[string]
  foreach($fp in $FilesAbs){
    if(-not (Test-Path -LiteralPath $fp -PathType Leaf)){ Fail ("SHA256SUMS_MISSING_FILE: " + $fp) }
    $hex = Sha256Hex $fp
    $rel = RelPath $Root $fp
    [void]$rows.Add(($hex + "  " + $rel))
  }
  WriteUtf8NoBomLfText $OutPath ((@($rows.ToArray()) -join "`n") + "`n")
}
function RunChild([string]$PSExe,[string]$ScriptPath,[string]$RepoRoot,[string]$HandoffDir,[string]$StdOut,[string]$StdErr){
  if(Test-Path -LiteralPath $StdOut -PathType Leaf){ Remove-Item -LiteralPath $StdOut -Force }
  if(Test-Path -LiteralPath $StdErr -PathType Leaf){ Remove-Item -LiteralPath $StdErr -Force }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $PSExe
  $psi.Arguments = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -RepoRoot "{1}" -HandoffDir "{2}"' -f $ScriptPath,$RepoRoot,$HandoffDir)
  $psi.WorkingDirectory = $RepoRoot
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true

  $pp = New-Object System.Diagnostics.Process
  $pp.StartInfo = $psi
  $null = $pp.Start()
  $so = $pp.StandardOutput.ReadToEnd()
  $se = $pp.StandardError.ReadToEnd()
  $pp.WaitForExit()

  WriteUtf8NoBomLfText $StdOut $so
  WriteUtf8NoBomLfText $StdErr $se

  return @{
    exit   = [int]$pp.ExitCode
    stdout = $so
    stderr = $se
  }
}
function AssertContains([string]$Hay,[string]$Needle,[string]$FailToken){
  if($null -eq $Hay){ $Hay = "" }
  if($Hay -notmatch [regex]::Escape($Needle)){
    Fail ($FailToken + ":MISSING_NEEDLE:" + $Needle)
  }
}

$RepoRoot   = (Resolve-Path -LiteralPath $RepoRoot).Path
$HandoffDir = (Resolve-Path -LiteralPath $HandoffDir).Path

$ScriptsDir = Join-Path $RepoRoot "scripts"
$ProofsDir  = Join-Path $RepoRoot "proofs"
$RcptRoot   = Join-Path $ProofsDir "receipts"

EnsureDir $ProofsDir
EnsureDir $RcptRoot

$Consumer = Join-Path $ScriptsDir "watchtower_consume_nfl_handoff_v1.ps1"
if(-not (Test-Path -LiteralPath $Consumer -PathType Leaf)){ Fail ("MISSING_CONSUMER_SCRIPT: " + $Consumer) }
if(-not (Test-Path -LiteralPath $HandoffDir -PathType Container)){ Fail ("MISSING_HANDOFF_DIR: " + $HandoffDir) }

# parse-gate locked surfaces
ParseGateFile $Consumer
ParseGateFile (Join-Path $ScriptsDir "_selftest_watchtower_consume_nfl_handoff_v1.ps1")
Write-Output "PARSE_GATE_OK"

$stamp  = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$bundle = Join-Path $RcptRoot $stamp
EnsureDir $bundle

$out1 = Join-Path $bundle "watchtower_consume_nfl_handoff.stdout.txt"
$err1 = Join-Path $bundle "watchtower_consume_nfl_handoff.stderr.txt"

$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source
$r = RunChild $PSExe $Consumer $RepoRoot $HandoffDir $out1 $err1

if($r.exit -ne 0){
  Write-Output ("CONSUME_EXIT=" + $r.exit)
  Fail "CONSUME_SCRIPT_FAILED"
}

AssertContains $r.stdout "HANDOFF_SHA256SUMS_OK" "CONSUME_BAD_STDOUT"
AssertContains $r.stdout "WATCHTOWER_CONSUME_NFL_OK" "CONSUME_BAD_STDOUT"
AssertContains $r.stdout "RECEIPT_APPEND_OK:" "CONSUME_BAD_STDOUT"

$receiptPath = Join-Path $bundle "watchtower.selftest.consume_nfl_handoff.v1.ndjson"
$obj = [ordered]@{
  schema = "watchtower.selftest.consume_nfl_handoff.v1"
  utc = $stamp
  ok = $true
  repo_root = $RepoRoot
  handoff_dir = $HandoffDir
  consume_script = $Consumer
  consume_exit = [int]$r.exit
  bundle_dir = $bundle
}
$line = ($obj | ConvertTo-Json -Compress)
WriteUtf8NoBomLfText $receiptPath ($line + "`n")

$files = @(Get-ChildItem -LiteralPath $bundle -Recurse -File | Sort-Object FullName)
$abs = New-Object System.Collections.Generic.List[string]
foreach($f in $files){ [void]$abs.Add($f.FullName) }

$sumPath = Join-Path $bundle "sha256sums.txt"
WriteSha256Sums $bundle $sumPath ($abs.ToArray())

Write-Output "WATCHTOWER_SELFTEST_CONSUME_NFL_OK"
Write-Output ("BUNDLE_DIR=" + $bundle)
