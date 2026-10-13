param(
  [Parameter(Mandatory=$true)][string]$PacketId
)

$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

# Project-local paths (was C:\ProgramData): this repository's packets\outbox and the
# sibling NFL checkout's packets\inbox.
$RepoRoot = Split-Path -Parent $PSScriptRoot
$src = Join-Path (Join-Path $RepoRoot "packets\outbox") $PacketId
$dst = Join-Path (Join-Path (Split-Path -Parent $RepoRoot) "nfl\packets\inbox") $PacketId

if(-not(Test-Path -LiteralPath $src)){ throw "Missing source packet: $src" }

# Ensure destination does not partially exist
if(Test-Path -LiteralPath $dst){
  throw "Destination already exists (refuse overwrite): $dst"
}

New-Item -ItemType Directory -Force -Path $dst | Out-Null

# Byte-identical copy (preserve structure; content is what matters)
Copy-Item -LiteralPath (Join-Path $src "*") -Destination $dst -Recurse -Force

Write-Host "OK: duplicated packet to NFL inbox"
Write-Host ("SRC: {0}" -f $src)
Write-Host ("DST: {0}" -f $dst)