param(
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$RepoRoot,

  [string]$Tenant = "single-tenant",
  [string]$Producer = "watchtower",
  [string]$ProducerInstance = "watchtower-local-1",

  # Empty defaults resolve inside this repository and its sibling NFL checkout
  # (formerly fixed folders on C:).
  [string]$AuthorityKey = "",
  [string]$Principal = "single-tenant/watchtower_authority/authority/watchtower",
  [string]$KeyId = "watchtower-authority-ed25519",

  [string]$Outbox = "",
  [string]$PledgesDir = "",
  [string]$NflInbox = ""
  ,
  [switch]$PauseOnExit
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if([string]::IsNullOrWhiteSpace($AuthorityKey)){ $AuthorityKey = Join-Path $RepoRoot "proofs\keys\watchtower_authority_ed25519" }
if([string]::IsNullOrWhiteSpace($Outbox)){ $Outbox = Join-Path $RepoRoot "packets\outbox" }
if([string]::IsNullOrWhiteSpace($PledgesDir)){ $PledgesDir = Join-Path $RepoRoot "proofs\pledges" }
if([string]::IsNullOrWhiteSpace($NflInbox)){ $NflInbox = Join-Path (Split-Path -Parent $RepoRoot) "nfl\packets\inbox" }

. (Join-Path $RepoRoot "scripts\_lib_watchtower_canon_v1.ps1")

function New-HT() { New-Object System.Collections.Hashtable }

function BuildManifestCore([string]$PacketDir) {
  $created = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $filesArr = @()
  $all = Get-ChildItem -LiteralPath $PacketDir -File -Recurse |
    Where-Object { $_.Name -ne "manifest.json" -and $_.Name -ne "sha256sums.txt" } |
    Sort-Object FullName
  foreach ($f in $all) {
    $rel = RelPathUnix $PacketDir $f.FullName
    $h = Sha256HexPath $f.FullName
    $obj = New-HT; $obj["path"]=$rel; $obj["bytes"]=[int64]$f.Length; $obj["sha256"]=$h
    $filesArr += $obj
  }
  $core = New-HT
  $core["schema"]="packet_manifest.v1"
  $core["producer"]=$Producer
  $core["producer_instance"]=$ProducerInstance
  $core["created_at_utc"]=$created
  $core["files"]=@($filesArr)
  return $core
}

function PacketIdFromCore([hashtable]$Core) {
  $json = (To-CanonJson $Core 60) + "`n"
  return Sha256HexBytes ([System.Text.Encoding]::UTF8.GetBytes($json))
}

function WriteManifest([string]$PacketDir, [hashtable]$Core, [string]$PacketId) {
  $m = New-HT
  $m["schema"]=$Core.schema
  $m["packet_id"]=$PacketId
  $m["producer"]=$Core.producer
  $m["producer_instance"]=$Core.producer_instance
  $m["created_at_utc"]=$Core.created_at_utc
  $m["files"]=$Core.files
  Write-Utf8NoBom (Join-Path $PacketDir "manifest.json") ((To-CanonJson $m 60) + "`n")
}

function WriteSha256Sums_NoSelf([string]$PacketDir) {
  $lines = @()
  $all = Get-ChildItem -LiteralPath $PacketDir -File -Recurse | Where-Object { $_.Name -ne "sha256sums.txt" } | Sort-Object FullName
  foreach ($f in $all) {
    $rel = RelPathUnix $PacketDir $f.FullName
    $h   = Sha256HexPath $f.FullName
    $lines += ("{0}  {1}" -f $h, $rel)
  }
  Write-Utf8NoBom (Join-Path $PacketDir "sha256sums.txt") (($lines -join "`n") + "`n")
}

function BuildPacket() {
  Ensure-Dir $Outbox
  $tmp = Join-Path $Outbox ("_tmp_" + [Guid]::NewGuid().ToString("N"))
  $payloadDir = Join-Path $tmp "payload"
  $sigDir     = Join-Path $tmp "signatures"
  try {
    Ensure-Dir $payloadDir; Ensure-Dir $sigDir
    # TODO: write payload + signature files here (left intact for now)
    $core = BuildManifestCore -PacketDir $tmp
    $packetId = PacketIdFromCore $core
    WriteManifest -PacketDir $tmp -Core $core -PacketId $packetId
    WriteSha256Sums_NoSelf -PacketDir $tmp
    $final = Join-Path $Outbox $packetId
    if (Test-Path -LiteralPath $final) { Remove-Item -LiteralPath $final -Recurse -Force }
    Move-Item -LiteralPath $tmp -Destination $final -Force
    Ensure-Dir $NflInbox
    $dest = Join-Path $NflInbox $packetId
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    Copy-Item -LiteralPath $final -Destination $dest -Recurse -Force
    return $packetId
  } catch {
    try { if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Recurse -Force } } catch { }
    throw
  }
}

$packetId = BuildPacket
Write-Host ("OK: PacketId: {0}" -f $packetId) -ForegroundColor Green
# --- optional pause (debug / keep window open) ---
if ($PauseOnExit) {
  Write-Host "Press Enter to close..." -ForegroundColor Yellow
  [void][System.Console]::ReadLine()
}

