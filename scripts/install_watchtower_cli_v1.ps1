param(
  # Default: <RepoRoot>\local\WatchTowerCLI inside the project (was %LOCALAPPDATA%\WatchTowerCLI).
  [string]$InstallRoot = "",
  [string]$RepoRoot = "",
  [switch]$UseLocalRelease,
  # Off by default: adding the install folder to the user PATH changes the user profile.
  [switch]$AddToUserPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function WT-Die([string]$m){
  throw ("WATCHTOWER_CLI_INSTALL_FAIL: " + $m)
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

function WT-RemoveIfExists([string]$p){
  if(Test-Path -LiteralPath $p){
    Remove-Item -LiteralPath $p -Recurse -Force
  }
}

function WT-AddToUserPath([string]$Dir){
  $current = [Environment]::GetEnvironmentVariable("Path","User")
  if($null -eq $current){ $current = "" }

  $parts = @($current -split ";" | Where-Object { $_ -and $_.Trim().Length -gt 0 })
  $exists = $false

  foreach($p in $parts){
    if($p.Trim().ToLowerInvariant() -eq $Dir.Trim().ToLowerInvariant()){
      $exists = $true
      break
    }
  }

  if(-not $exists){
    $newPath = if([string]::IsNullOrWhiteSpace($current)){
      $Dir
    }
    else {
      $current.TrimEnd(";") + ";" + $Dir
    }
    [Environment]::SetEnvironmentVariable("Path",$newPath,"User")
  }

  $userPath = [Environment]::GetEnvironmentVariable("Path","User")
  $machinePath = [Environment]::GetEnvironmentVariable("Path","Machine")
  if($null -eq $userPath){ $userPath = "" }
  if($null -eq $machinePath){ $machinePath = "" }
  $env:PATH = $userPath + ";" + $machinePath
}

$zipUrl = "https://github.com/ScrappyHub/WatchTower/releases/download/watchtower-cli-v1.0.1/watchtower_cli_v1.zip"

if([string]::IsNullOrWhiteSpace($RepoRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)){
  $RepoRoot = Split-Path -Parent $PSScriptRoot
}
if(Test-Path -LiteralPath $RepoRoot -PathType Container){
  $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
}

if([string]::IsNullOrWhiteSpace($RepoRoot) -or -not (Test-Path -LiteralPath $RepoRoot -PathType Container)){
  # Run remotely (iwr | iex): there is no repository; install under the current folder.
  $RepoRoot = (Get-Location).Path
}
if([string]::IsNullOrWhiteSpace($InstallRoot)){
  $InstallRoot = Join-Path $RepoRoot "local\WatchTowerCLI"
}
WT-EnsureDir $InstallRoot

# Scratch stays inside the project (never %TEMP%).
$scratch = Join-Path $RepoRoot ".scratch"
WT-EnsureDir $scratch
$tempZip = Join-Path $scratch "watchtower_cli_v1.zip"
$tempExtract = Join-Path $scratch "watchtower_cli_v1_extract"

WT-RemoveIfExists $tempZip
WT-RemoveIfExists $tempExtract

if($UseLocalRelease){
  $localZip = Join-Path $RepoRoot "release\watchtower_cli_v1.zip"
  if(-not (Test-Path -LiteralPath $localZip -PathType Leaf)){
    WT-Die ("LOCAL_RELEASE_ZIP_MISSING: " + $localZip)
  }
  Copy-Item -LiteralPath $localZip -Destination $tempZip -Force
}
else {
  Invoke-WebRequest -Uri $zipUrl -OutFile $tempZip
}

Expand-Archive -LiteralPath $tempZip -DestinationPath $tempExtract -Force

$dirs = @(Get-ChildItem -LiteralPath $tempExtract -Directory -ErrorAction SilentlyContinue)
if(@($dirs).Count -eq 1){
  $bundleRoot = $dirs[0].FullName
}
else {
  $bundleRoot = $tempExtract
}

$cliEntry = Join-Path $bundleRoot "scripts\watchtower_cli_v1.ps1"
if(-not (Test-Path -LiteralPath $cliEntry -PathType Leaf)){
  WT-Die ("CLI_ENTRY_NOT_FOUND_IN_BUNDLE: " + $bundleRoot)
}

$finalRoot = Join-Path $InstallRoot "watchtower_cli_v1"
WT-RemoveIfExists $finalRoot
Copy-Item -LiteralPath $bundleRoot -Destination $finalRoot -Recurse -Force

$watchtowerCmd = Join-Path $InstallRoot "watchtower.cmd"
$watchtowerCliCmd = Join-Path $InstallRoot "watchtower-cli.cmd"
$cliScript = Join-Path $finalRoot "scripts\watchtower_cli_v1.ps1"

# Relative to the launcher's own folder (%~dp0), so the install keeps working if the
# project folder moves (for example from C: to S:).
$launcherTxt = '@echo off' + "`n" +
'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0watchtower_cli_v1\scripts\watchtower_cli_v1.ps1" -RepoRoot "%~dp0watchtower_cli_v1" %*'

WT-WriteUtf8NoBomLf -Path $watchtowerCmd -Text $launcherTxt
WT-WriteUtf8NoBomLf -Path $watchtowerCliCmd -Text $launcherTxt

$uninstallPath = Join-Path $InstallRoot "uninstall_watchtower_cli_v1.ps1"
$uninstallTxt = @'
param(
  # The folder this uninstaller was installed into.
  [string]$InstallRoot = $PSScriptRoot
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$bundle = Join-Path $InstallRoot "watchtower_cli_v1"
$cmd1 = Join-Path $InstallRoot "watchtower.cmd"
$cmd2 = Join-Path $InstallRoot "watchtower-cli.cmd"

if(Test-Path -LiteralPath $bundle){ Remove-Item -LiteralPath $bundle -Recurse -Force }
if(Test-Path -LiteralPath $cmd1){ Remove-Item -LiteralPath $cmd1 -Force }
if(Test-Path -LiteralPath $cmd2){ Remove-Item -LiteralPath $cmd2 -Force }

$current = [Environment]::GetEnvironmentVariable("Path","User")
if($null -eq $current){ $current = "" }
$parts = @($current -split ";" | Where-Object { $_ -and $_.Trim().Length -gt 0 })
$filtered = @()
foreach($p in $parts){
  if($p.Trim().ToLowerInvariant() -ne $InstallRoot.Trim().ToLowerInvariant()){
    $filtered += $p
  }
}
[Environment]::SetEnvironmentVariable("Path",($filtered -join ";"),"User")

Write-Host "WATCHTOWER_CLI_UNINSTALL_OK" -ForegroundColor Green
Write-Host ("INSTALL_ROOT: " + $InstallRoot) -ForegroundColor Green
'@
WT-WriteUtf8NoBomLf -Path $uninstallPath -Text $uninstallTxt

if($AddToUserPath){ WT-AddToUserPath $InstallRoot }
else { Write-Host ("PATH_UNCHANGED: run " + (Join-Path $InstallRoot "watchtower.cmd") + " directly, or reinstall with -AddToUserPath") -ForegroundColor Green }





Write-Host "WATCHTOWER_CLI_INSTALL_OK" -ForegroundColor Green
Write-Host ("INSTALL_ROOT: " + $InstallRoot) -ForegroundColor Green
Write-Host ("BUNDLE_ROOT: " + $finalRoot) -ForegroundColor Green
Write-Host ("LAUNCHER: " + $watchtowerCmd) -ForegroundColor Green
Write-Host ("COMPAT_LAUNCHER: " + $watchtowerCliCmd) -ForegroundColor Green
Write-Host ("UNINSTALLER: " + $uninstallPath) -ForegroundColor Green
Write-Host "TRY_NOW: watchtower version" -ForegroundColor Green
Write-Host "TRY_NOW: watchtower doctor" -ForegroundColor Green
Write-Host "TRY_NOW: watchtower status" -ForegroundColor Green
Write-Host "TRY_NOW: watchtower receipts summary" -ForegroundColor Green
Write-Host "TRY_NOW: watchtower quick-check" -ForegroundColor Green
Write-Host "REMOTE_INSTALL: iwr https://raw.githubusercontent.com/ScrappyHub/WatchTower/master/scripts/install_watchtower_cli_v1.ps1 | iex" -ForegroundColor Green
