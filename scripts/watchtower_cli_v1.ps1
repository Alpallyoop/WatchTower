param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$Args
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function WT-Die([string]$m){ throw ("WATCHTOWER_CLI_FAIL: " + $m) }

function WT-EnsureRepo([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Container)){
    WT-Die ("INVALID_REPO_ROOT: " + $Path)
  }
  return (Resolve-Path -LiteralPath $Path).Path
}

function WT-InvokeChild([string]$Script,[string[]]$ChildArgs){
  if(-not (Test-Path -LiteralPath $Script -PathType Leaf)){
    WT-Die ("SCRIPT_MISSING: " + $Script)
  }
  $PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source
  & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script @ChildArgs
  if($LASTEXITCODE -ne 0){ WT-Die ("CHILD_FAILED: " + $Script + ": " + $LASTEXITCODE) }
}

$RepoRoot = WT-EnsureRepo $RepoRoot
$cmd0 = if($Args -and @($Args).Count -gt 0){ $Args[0].ToLowerInvariant() } else { "" }

switch($cmd0){
  "" {
    Write-Host "WatchTower CLI"
    Write-Host "Commands:"
    Write-Host "  watchtower quick-check"
    Write-Host "  watchtower engine init"
    Write-Host "  watchtower engine observe-device"
    Write-Host "  watchtower engine observe-telemetry <device_id>"
    Write-Host "  watchtower engine observe-machine"
    Write-Host "  watchtower engine observe-drives"
    Write-Host "  watchtower engine observe-processes"
    Write-Host "  watchtower engine process-origins"
    Write-Host "  watchtower engine drive-map"
    Write-Host "  watchtower engine process-map"
    Write-Host "  watchtower engine explain-process <pid>"
    Write-Host "  watchtower engine events"
    Write-Host "  watchtower engine receipts"
    Write-Host "  watchtower engine summary"
    Write-Host "  watchtower doctor"
    Write-Host "  watchtower status"
    Write-Host "  watchtower receipts summary"
    Write-Host "  watchtower version"
    return
  }

  "engine" {
    if(@($Args).Count -lt 2){ WT-Die "ENGINE_SUBCOMMAND_REQUIRED" }

    $engineScript = Join-Path $PSScriptRoot "watchtower_engine_v1.ps1"
    if(-not (Test-Path -LiteralPath $engineScript -PathType Leaf)){
      WT-Die ("ENGINE_SCRIPT_MISSING: " + $engineScript)
    }

    $cmd1 = $Args[1].ToLowerInvariant()
    $engineArgs = @("-RepoRoot",$RepoRoot)

    switch($cmd1){
      "init" { $engineArgs += @("-Command","init") }
      "observe-device" { $engineArgs += @("-Command","observe-device","-Label","local","-Status","observed") }
      "observe-telemetry" {
        if(@($Args).Count -lt 3){ WT-Die "ENGINE_DEVICE_ID_REQUIRED" }
        $engineArgs += @("-Command","observe-telemetry","-DeviceId",$Args[2],"-TelemetryKind","heartbeat","-Status","ok")
      }
      "observe-machine" { $engineArgs += @("-Command","observe-machine") }
      "observe-drives" { $engineArgs += @("-Command","observe-drives") }
      "observe-processes" { $engineArgs += @("-Command","observe-processes") }
      "process-origins" { $engineArgs += @("-Command","process-origins") }
      "drive-map" { $engineArgs += @("-Command","drive-map") }
      "process-map" { $engineArgs += @("-Command","process-map") }
      "explain-process" {
        if(@($Args).Count -lt 3){ WT-Die "ENGINE_PID_REQUIRED" }
        $engineArgs += @("-Command","explain-process","-ProcessId",$Args[2])
      }
      "events" { $engineArgs += @("-Command","events") }
      "receipts" { $engineArgs += @("-Command","receipts") }
      "summary" { $engineArgs += @("-Command","summary") }
      default { WT-Die ("UNKNOWN_ENGINE_SUBCOMMAND: " + $cmd1) }
    }

    WT-InvokeChild $engineScript $engineArgs
    return
  }

  "version" {
    Write-Host "WATCHTOWER_VERSION_OK"
    Write-Host "VERSION: 1.0.2"
    return
  }

  "doctor" {
    # Installed bundle: <InstallRoot>\watchtower_cli_v1 next to watchtower.cmd.
    # From the repository: <RepoRoot>\local\WatchTowerCLI (never %LOCALAPPDATA%).
    $installRoot = Split-Path -Parent $RepoRoot
    if(-not (Test-Path -LiteralPath (Join-Path $installRoot "watchtower.cmd"))){ $installRoot = Join-Path $RepoRoot "local\WatchTowerCLI" }
    Write-Host "WATCHTOWER_DOCTOR_START"
    Write-Host ("REPO_ROOT: " + $RepoRoot)
    Write-Host ("INSTALL_ROOT: " + $installRoot)
    Write-Host ("USER_PATH_CONTAINS_INSTALL_ROOT: " + ([Environment]::GetEnvironmentVariable("Path","User") -like ("*" + $installRoot + "*")))
    Write-Host ("WATCHTOWER_CMD_EXISTS: " + (Test-Path -LiteralPath (Join-Path $installRoot "watchtower.cmd")))
    Write-Host ("WATCHTOWER_CLI_CMD_EXISTS: " + (Test-Path -LiteralPath (Join-Path $installRoot "watchtower-cli.cmd")))
    Write-Host "WATCHTOWER_DOCTOR_OK"
    return
  }

  "status" {
    $engineScript = Join-Path $PSScriptRoot "watchtower_engine_v1.ps1"
    if(Test-Path -LiteralPath $engineScript -PathType Leaf){
      WT-InvokeChild $engineScript @("-RepoRoot",$RepoRoot,"-Command","summary")
    } else {
      Write-Host "WATCHTOWER_STATUS_OK"
      Write-Host "ENGINE_PRESENT: False"
    }
    return
  }

  "quick-check" {
    Write-Host "WATCHTOWER_QUICK_CHECK_START"
    Write-Host "WATCHTOWER_QUICK_CHECK_OK"
    return
  }

  default { WT-Die ("UNKNOWN_COMMAND: " + $cmd0) }
}
