param(
  [string]$Tag = "watchtower-cli-v1.0.1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$zip = Join-Path (Split-Path -Parent $PSScriptRoot) "release\watchtower_cli_v1.zip"
if(-not (Test-Path -LiteralPath $zip -PathType Leaf)){
  throw "ZIP_MISSING"
}

$notes = @"
WatchTower CLI v1.0.1

- installable CLI
- quick-check command
- PATH + launcher support
"@

$cmd = 'gh release view "' + $Tag + '" >nul 2>nul'
cmd.exe /c $cmd
$exists = ($LASTEXITCODE -eq 0)

if($exists){
  & gh release upload $Tag $zip --clobber
  if($LASTEXITCODE -ne 0){
    throw "GH_RELEASE_UPLOAD_FAILED"
  }

  & gh release edit $Tag --title "WatchTower CLI v1.0.1" --notes $notes
  if($LASTEXITCODE -ne 0){
    throw "GH_RELEASE_EDIT_FAILED"
  }
}
else {
  & gh release create $Tag $zip --title "WatchTower CLI v1.0.1" --notes $notes
  if($LASTEXITCODE -ne 0){
    throw "GH_RELEASE_CREATE_FAILED"
  }
}

Write-Host "WATCHTOWER_RELEASE_PUBLISH_OK" -ForegroundColor Green
Write-Host ("TAG: " + $Tag) -ForegroundColor Green
Write-Host ("ZIP: " + $zip) -ForegroundColor Green
