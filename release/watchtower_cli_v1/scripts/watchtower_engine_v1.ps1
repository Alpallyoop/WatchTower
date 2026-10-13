param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$Command,
  [string]$DeviceId = "",
  [string]$Label = "",
  [string]$OsFamily = "windows",
  [string]$TrustLevel = "T1",
  [string]$Status = "observed",
  [string]$TelemetryKind = "heartbeat",
  [string]$ProcessId = ""
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function WT-Die([string]$m){ throw ("WATCHTOWER_ENGINE_FAIL: " + $m) }

function WT-EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ return }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WT-WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $dir = Split-Path -Parent $Path
  if($dir){ WT-EnsureDir $dir }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  [System.IO.File]::WriteAllText($Path,$t,$enc)
}

function WT-AppendUtf8NoBomLf([string]$Path,[string]$Text){
  $dir = Split-Path -Parent $Path
  if($dir){ WT-EnsureDir $dir }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  [System.IO.File]::AppendAllText($Path,$t,$enc)
}

function WT-Sha256HexText([string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $bytes = $enc.GetBytes($Text)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
  }
  finally { $sha.Dispose() }
}

function WT-EscapeJson([string]$s){
  if($null -eq $s){ return "" }
  return $s.Replace("\","\\").Replace('"','\"').Replace("`r","\r").Replace("`n","\n").Replace("`t","\t")
}

function WT-JsonPair([string]$k,[string]$v){
  return '"' + (WT-EscapeJson $k) + '":"' + (WT-EscapeJson $v) + '"'
}

function WT-Receipt([string]$Kind,[string]$PayloadJson){
  $utc = [DateTime]::UtcNow.ToString("o")
  $hash = WT-Sha256HexText $PayloadJson
  return '{"schema":"watchtower.engine.receipt.v1","utc":"' + $utc + '","kind":"' + (WT-EscapeJson $Kind) + '","payload_hash":"' + $hash + '","payload":' + $PayloadJson + '}'
}

function WT-Event([string]$Kind,[string]$PayloadJson){
  $utc = [DateTime]::UtcNow.ToString("o")
  $hash = WT-Sha256HexText $PayloadJson
  return '{"schema":"watchtower.engine.event.v1","utc":"' + $utc + '","kind":"' + (WT-EscapeJson $Kind) + '","payload_hash":"' + $hash + '","payload":' + $PayloadJson + '}'
}

function WT-AppendObservation([string]$Kind,[string]$PayloadJson){
  WT-AppendUtf8NoBomLf -Path $EngineReceipt -Text (WT-Receipt $Kind $PayloadJson)
  WT-AppendUtf8NoBomLf -Path $EventsPath -Text (WT-Event $Kind $PayloadJson)
}

function WT-ReadLinesCount([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ return 0 }
  return @([System.IO.File]::ReadAllLines($Path)).Count
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$RuntimeRoot = Join-Path $RepoRoot "runtime\watchtower_engine_v1"
$DevicesRoot = Join-Path $RuntimeRoot "devices"
$TelemetryRoot = Join-Path $RuntimeRoot "telemetry"
$MachineRoot = Join-Path $RuntimeRoot "machine"
$DrivesRoot = Join-Path $RuntimeRoot "drives"
$ProcessesRoot = Join-Path $RuntimeRoot "processes"
$EventsPath = Join-Path $RuntimeRoot "events.ndjson"

$ReceiptsRoot = Join-Path $RepoRoot "proofs\receipts"
$EngineReceipt = Join-Path $ReceiptsRoot "watchtower_engine_v1.ndjson"

foreach($p in @($RuntimeRoot,$DevicesRoot,$TelemetryRoot,$MachineRoot,$DrivesRoot,$ProcessesRoot,$ReceiptsRoot)){
  WT-EnsureDir $p
}

$cmd = $Command.ToLowerInvariant()

switch($cmd){
  "init" {
    $payload = '{"runtime_root":"' + (WT-EscapeJson $RuntimeRoot) + '","devices_root":"' + (WT-EscapeJson $DevicesRoot) + '","telemetry_root":"' + (WT-EscapeJson $TelemetryRoot) + '","machine_root":"' + (WT-EscapeJson $MachineRoot) + '","drives_root":"' + (WT-EscapeJson $DrivesRoot) + '"}'
    WT-AppendObservation "engine.init" $payload
    Write-Host "WATCHTOWER_ENGINE_INIT_OK"
    Write-Host ("RUNTIME_ROOT: " + $RuntimeRoot)
    Write-Host ("DEVICES_ROOT: " + $DevicesRoot)
    Write-Host ("TELEMETRY_ROOT: " + $TelemetryRoot)
    Write-Host ("MACHINE_ROOT: " + $MachineRoot)
    Write-Host ("DRIVES_ROOT: " + $DrivesRoot)
    return
  }

  "observe-device" {
    if([string]::IsNullOrWhiteSpace($DeviceId)){
      $seed = $env:COMPUTERNAME + "|" + $env:USERNAME + "|" + $OsFamily + "|" + $Label
      $DeviceId = WT-Sha256HexText $seed
    }
    if([string]::IsNullOrWhiteSpace($Label)){ $Label = $env:COMPUTERNAME }

    $deviceRoot = Join-Path $DevicesRoot $DeviceId
    WT-EnsureDir $deviceRoot

    $devicePath = Join-Path $deviceRoot "device.json"
    $payload = '{"device_id":"' + (WT-EscapeJson $DeviceId) + '","label":"' + (WT-EscapeJson $Label) + '","os_family":"' + (WT-EscapeJson $OsFamily) + '","trust_level":"' + (WT-EscapeJson $TrustLevel) + '","status":"' + (WT-EscapeJson $Status) + '"}'
    WT-WriteUtf8NoBomLf -Path $devicePath -Text $payload
    WT-AppendObservation "device.observe" $payload

    Write-Host "WATCHTOWER_ENGINE_DEVICE_OBSERVE_OK"
    Write-Host ("DEVICE_ID: " + $DeviceId)
    Write-Host ("DEVICE_PATH: " + $devicePath)
    return
  }

  "observe-telemetry" {
    if([string]::IsNullOrWhiteSpace($DeviceId)){ WT-Die "DEVICE_ID_REQUIRED" }

    $deviceRoot = Join-Path $DevicesRoot $DeviceId
    $devicePath = Join-Path $deviceRoot "device.json"
    if(-not (Test-Path -LiteralPath $devicePath -PathType Leaf)){
      WT-Die ("DEVICE_NOT_FOUND: " + $DeviceId)
    }

    $telemetryPath = Join-Path $TelemetryRoot ($DeviceId + ".ndjson")
    $utc = [DateTime]::UtcNow.ToString("o")
    $payload = '{"device_id":"' + (WT-EscapeJson $DeviceId) + '","kind":"' + (WT-EscapeJson $TelemetryKind) + '","utc":"' + $utc + '","status":"' + (WT-EscapeJson $Status) + '"}'
    WT-AppendUtf8NoBomLf -Path $telemetryPath -Text $payload
    WT-AppendObservation "telemetry.observe" $payload

    Write-Host "WATCHTOWER_ENGINE_TELEMETRY_OBSERVE_OK"
    Write-Host ("DEVICE_ID: " + $DeviceId)
    Write-Host ("TELEMETRY_PATH: " + $telemetryPath)
    return
  }

  "observe-machine" {
    $os = Get-CimInstance Win32_OperatingSystem
    $bios = Get-CimInstance Win32_BIOS
    $cs = Get-CimInstance Win32_ComputerSystem

    $machineSeed = $env:COMPUTERNAME + "|" + $env:USERNAME + "|" + [string]$bios.SerialNumber + "|" + [string]$cs.Manufacturer + "|" + [string]$cs.Model
    $machineId = WT-Sha256HexText $machineSeed

    $machinePath = Join-Path $MachineRoot "machine.json"
    $payload = '{' +
      (WT-JsonPair "machine_id" $machineId) + ',' +
      (WT-JsonPair "computer_name" $env:COMPUTERNAME) + ',' +
      (WT-JsonPair "username" $env:USERNAME) + ',' +
      (WT-JsonPair "os_caption" ([string]$os.Caption)) + ',' +
      (WT-JsonPair "os_version" ([string]$os.Version)) + ',' +
      (WT-JsonPair "manufacturer" ([string]$cs.Manufacturer)) + ',' +
      (WT-JsonPair "model" ([string]$cs.Model)) + ',' +
      (WT-JsonPair "bios_serial_hash" (WT-Sha256HexText ([string]$bios.SerialNumber)) ) +
    '}'

    WT-WriteUtf8NoBomLf -Path $machinePath -Text $payload
    WT-AppendObservation "machine.observe" $payload

    Write-Host "WATCHTOWER_ENGINE_MACHINE_OBSERVE_OK"
    Write-Host ("MACHINE_ID: " + $machineId)
    Write-Host ("MACHINE_PATH: " + $machinePath)
    return
  }

  "observe-drives" {
    $diskItems = @()
    $disks = @(Get-Disk | Sort-Object Number)
    foreach($d in $disks){
      $seed = ([string]$d.Number + "|" + [string]$d.UniqueId + "|" + [string]$d.SerialNumber + "|" + [string]$d.Size + "|" + [string]$d.FriendlyName)
      $diskId = WT-Sha256HexText $seed
      $diskItems += ('{"disk_id":"' + $diskId + '","number":"' + (WT-EscapeJson ([string]$d.Number)) + '","friendly_name":"' + (WT-EscapeJson ([string]$d.FriendlyName)) + '","serial_hash":"' + (WT-Sha256HexText ([string]$d.SerialNumber)) + '","size":"' + (WT-EscapeJson ([string]$d.Size)) + '","partition_style":"' + (WT-EscapeJson ([string]$d.PartitionStyle)) + '","health_status":"' + (WT-EscapeJson ([string]$d.HealthStatus)) + '","operational_status":"' + (WT-EscapeJson ([string]$d.OperationalStatus)) + '"}')
    }

    $volumeItems = @()
    $vols = @(Get-Volume | Sort-Object DriveLetter,FileSystemLabel)
    foreach($v in $vols){
      $volSeed = ([string]$v.DriveLetter + "|" + [string]$v.FileSystemLabel + "|" + [string]$v.FileSystem + "|" + [string]$v.Size)
      $volId = WT-Sha256HexText $volSeed
      $volumeItems += ('{"volume_id":"' + $volId + '","drive_letter":"' + (WT-EscapeJson ([string]$v.DriveLetter)) + '","filesystem":"' + (WT-EscapeJson ([string]$v.FileSystem)) + '","label":"' + (WT-EscapeJson ([string]$v.FileSystemLabel)) + '","size":"' + (WT-EscapeJson ([string]$v.Size)) + '","size_remaining":"' + (WT-EscapeJson ([string]$v.SizeRemaining)) + '","health_status":"' + (WT-EscapeJson ([string]$v.HealthStatus)) + '"}')
    }

    $drivesJson = '{"schema":"watchtower.drives.snapshot.v1","disks":[' + ($diskItems -join ",") + '],"volumes":[' + ($volumeItems -join ",") + ']}'
    $drivesPath = Join-Path $DrivesRoot "drives.json"
    WT-WriteUtf8NoBomLf -Path $drivesPath -Text $drivesJson
    WT-AppendObservation "drives.observe" $drivesJson

    Write-Host "WATCHTOWER_ENGINE_DRIVES_OBSERVE_OK"
    Write-Host ("DISKS: " + @($diskItems).Count)
    Write-Host ("VOLUMES: " + @($volumeItems).Count)
    Write-Host ("DRIVES_PATH: " + $drivesPath)
    return
  }

  "observe-processes" {
    $processItems = @()
    $originItems = @()

    $procs = @(Get-CimInstance Win32_Process | Sort-Object ProcessId)
    foreach($p in $procs){
      $pidText = [string]$p.ProcessId
      $nameText = [string]$p.Name
      $exeText = [string]$p.ExecutablePath
      $cmdText = [string]$p.CommandLine

      $driveRoot = ""
      $originKind = "unknown"
      $originReason = ""

      if(-not [string]::IsNullOrWhiteSpace($exeText)){
        if($exeText -match '^[A-Za-z]:\\'){
          $driveRoot = $exeText.Substring(0,2).ToUpperInvariant()
          $originKind = "local_drive"
          $originReason = "executable_path_has_drive"
        }
        elseif($exeText.StartsWith("\\\")){
          $originKind = "unc_path"
          $originReason = "executable_path_is_unc"
        }
        else {
          $originKind = "non_drive_path"
          $originReason = "executable_path_without_drive_root"
        }
      }
      else {
        if([string]::IsNullOrWhiteSpace($cmdText)){
          $originKind = "protected_or_system"
          $originReason = "missing_executable_and_command_line"
        }
        elseif($cmdText -match '^[A-Za-z]:\\'){
          $driveRoot = $cmdText.Substring(0,2).ToUpperInvariant()
          $originKind = "local_drive_from_command_line"
          $originReason = "command_line_has_drive"
        }
        elseif($cmdText -match '\\Windows\\system32\\|\\WINDOWS\\system32\\'){
          $driveRoot = $env:SystemDrive
          $originKind = "windows_system_process"
          $originReason = "command_line_mentions_system32"
        }
        elseif($nameText -match '^(System|Registry|Idle|smss\.exe|csrss\.exe|wininit\.exe|services\.exe|lsass\.exe|svchost\.exe|fontdrvhost\.exe|dwm\.exe)$'){
          $originKind = "windows_protected_process"
          $originReason = "known_protected_process_name"
        }
        else {
          $originKind = "unresolved_no_executable_path"
          $originReason = "missing_executable_path"
        }
      }

      $processIdHash = WT-Sha256HexText ($pidText + "|" + $nameText + "|" + $exeText + "|" + $cmdText)

      $processItems += ('{"process_hash":"' + $processIdHash + '","pid":"' + (WT-EscapeJson $pidText) + '","name":"' + (WT-EscapeJson $nameText) + '","executable_path":"' + (WT-EscapeJson $exeText) + '","command_line_hash":"' + (WT-Sha256HexText $cmdText) + '"}')
      $originItems += ('{"process_hash":"' + $processIdHash + '","pid":"' + (WT-EscapeJson $pidText) + '","name":"' + (WT-EscapeJson $nameText) + '","origin_kind":"' + (WT-EscapeJson $originKind) + '","drive_root":"' + (WT-EscapeJson $driveRoot) + '","executable_path":"' + (WT-EscapeJson $exeText) + '"}')
    }

    $processJson = '{"schema":"watchtower.process.snapshot.v1","processes":[' + ($processItems -join ",") + ']}'
    $originJson = '{"schema":"watchtower.process.origins.v1","origins":[' + ($originItems -join ",") + ']}'

    $processPath = Join-Path $ProcessesRoot "processes.json"
    $originPath = Join-Path $ProcessesRoot "process_origins.json"

    WT-WriteUtf8NoBomLf -Path $processPath -Text $processJson
    WT-WriteUtf8NoBomLf -Path $originPath -Text $originJson
    WT-AppendObservation "processes.observe" $processJson
    WT-AppendObservation "process_origins.observe" $originJson

    Write-Host "WATCHTOWER_ENGINE_PROCESSES_OBSERVE_OK"
    Write-Host ("PROCESS_COUNT: " + @($processItems).Count)
    Write-Host ("PROCESS_ORIGINS: " + @($originItems).Count)
    Write-Host ("PROCESSES_PATH: " + $processPath)
    Write-Host ("PROCESS_ORIGINS_PATH: " + $originPath)
    return
  }

  "process-origins" {
    $originPath = Join-Path $ProcessesRoot "process_origins.json"
    Write-Host "WATCHTOWER_ENGINE_PROCESS_ORIGINS_OK"
    Write-Host ("PROCESS_ORIGINS_PATH: " + $originPath)
    Write-Host ("PRESENT: " + (Test-Path -LiteralPath $originPath -PathType Leaf))
    return
  }
  "drive-map" {
    $drivesPath = Join-Path $DrivesRoot "drives.json"

    Write-Host "WATCHTOWER_ENGINE_DRIVE_MAP_OK"
    Write-Host ("DRIVES_PATH: " + $drivesPath)
    Write-Host ("PRESENT: " + (Test-Path -LiteralPath $drivesPath -PathType Leaf))

    if(Test-Path -LiteralPath $drivesPath -PathType Leaf){
      $obj = [System.IO.File]::ReadAllText($drivesPath,[System.Text.Encoding]::UTF8) | ConvertFrom-Json
      $disks = @($obj.disks)
      $vols = @($obj.volumes)

      Write-Host ("DISKS: " + $disks.Count)
      foreach($d in $disks){
        Write-Host ("DISK: number=" + [string]$d.number + " size=" + [string]$d.size + " health=" + [string]$d.health_status + " name=" + [string]$d.friendly_name)
      }

      Write-Host ("VOLUMES: " + $vols.Count)
      foreach($v in $vols){
        $letter = [string]$v.drive_letter
        if([string]::IsNullOrWhiteSpace($letter)){ $letter = "(none)" }
        Write-Host ("VOLUME: drive=" + $letter + " fs=" + [string]$v.filesystem + " label=" + [string]$v.label + " size=" + [string]$v.size + " remaining=" + [string]$v.size_remaining + " health=" + [string]$v.health_status)
      }
    }
    return
  }

  "explain-process" {
    if([string]::IsNullOrWhiteSpace($ProcessId)){
      WT-Die "PID_REQUIRED"
    }

    $originPath = Join-Path $ProcessesRoot "process_origins.json"
    if(-not (Test-Path -LiteralPath $originPath -PathType Leaf)){
      WT-Die ("PROCESS_ORIGINS_MISSING: " + $originPath)
    }

    $obj = [System.IO.File]::ReadAllText($originPath,[System.Text.Encoding]::UTF8) | ConvertFrom-Json
    $matches = @($obj.origins | Where-Object { [string]$_.pid -eq [string]$ProcessId })

    if(@($matches).Count -lt 1){
      WT-Die ("PROCESS_NOT_FOUND: " + $ProcessId)
    }

    $p = $matches[0]
    $reason = ""
    if($p.PSObject.Properties.Name -contains "origin_reason"){
      $reason = [string]$p.origin_reason
    }

    Write-Host "WATCHTOWER_ENGINE_EXPLAIN_PROCESS_OK"
    Write-Host ("PID: " + [string]$p.pid)
    Write-Host ("NAME: " + [string]$p.name)
    Write-Host ("ORIGIN_KIND: " + [string]$p.origin_kind)
    Write-Host ("ORIGIN_REASON: " + $reason)
    Write-Host ("DRIVE_ROOT: " + [string]$p.drive_root)
    Write-Host ("EXECUTABLE_PATH: " + [string]$p.executable_path)
    Write-Host ("PROCESS_HASH: " + [string]$p.process_hash)
    return
  }
  "process-map" {
    $originPath = Join-Path $ProcessesRoot "process_origins.json"

    Write-Host "WATCHTOWER_ENGINE_PROCESS_MAP_OK"
    Write-Host ("PROCESS_ORIGINS_PATH: " + $originPath)
    Write-Host ("PRESENT: " + (Test-Path -LiteralPath $originPath -PathType Leaf))

    if(Test-Path -LiteralPath $originPath -PathType Leaf){
      $obj = [System.IO.File]::ReadAllText($originPath,[System.Text.Encoding]::UTF8) | ConvertFrom-Json
      $origins = @($obj.origins)
      Write-Host ("PROCESS_ORIGINS: " + $origins.Count)

      $groups = $origins | Group-Object origin_kind,drive_root | Sort-Object Name
      foreach($g in $groups){
        Write-Host ("ORIGIN_GROUP: " + $g.Name + " COUNT=" + $g.Count)
      }

      $top = @($origins | Sort-Object name | Select-Object -First 25)
      foreach($p in $top){
        $reason = ""
if($p.PSObject.Properties.Name -contains "origin_reason"){
  $reason = [string]$p.origin_reason
}

Write-Host ("PROCESS: pid=" + [string]$p.pid + " name=" + [string]$p.name + " origin=" + [string]$p.origin_kind + " reason=" + $reason + " drive=" + [string]$p.drive_root + " path=" + [string]$p.executable_path)
      }
    }
    return
  }
  "events" {
    Write-Host "WATCHTOWER_ENGINE_EVENTS_OK"
    Write-Host ("EVENTS_PATH: " + $EventsPath)
    Write-Host ("COUNT: " + (WT-ReadLinesCount $EventsPath))
    return
  }

  "receipts" {
    Write-Host "WATCHTOWER_ENGINE_RECEIPTS_OK"
    Write-Host ("RECEIPT_PATH: " + $EngineReceipt)
    Write-Host ("COUNT: " + (WT-ReadLinesCount $EngineReceipt))
    return
  }

  "summary" {
    $deviceCount = 0
    $telemetryCount = 0
    $receiptCount = WT-ReadLinesCount $EngineReceipt
    $eventCount = WT-ReadLinesCount $EventsPath
    $machinePresent = Test-Path -LiteralPath (Join-Path $MachineRoot "machine.json") -PathType Leaf
    $drivesPresent = Test-Path -LiteralPath (Join-Path $DrivesRoot "drives.json") -PathType Leaf
    $processesPresent = Test-Path -LiteralPath (Join-Path $ProcessesRoot "processes.json") -PathType Leaf
    $processOriginsPresent = Test-Path -LiteralPath (Join-Path $ProcessesRoot "process_origins.json") -PathType Leaf
    $processCount = 0
    if($processesPresent){
      $procText = [System.IO.File]::ReadAllText((Join-Path $ProcessesRoot "processes.json"),[System.Text.Encoding]::UTF8)
      $processCount = ([regex]::Matches($procText,'"process_hash"')).Count
    }

    if(Test-Path -LiteralPath $DevicesRoot -PathType Container){
      $deviceCount = @((Get-ChildItem -LiteralPath $DevicesRoot -Directory -ErrorAction SilentlyContinue)).Count
    }
    if(Test-Path -LiteralPath $TelemetryRoot -PathType Container){
      $telemetryFiles = @(Get-ChildItem -LiteralPath $TelemetryRoot -File -ErrorAction SilentlyContinue)
      foreach($f in $telemetryFiles){
        $telemetryCount += @([System.IO.File]::ReadAllLines($f.FullName)).Count
      }
    }

    Write-Host "WATCHTOWER_ENGINE_SUMMARY_OK"
    Write-Host ("DEVICES: " + $deviceCount)
    Write-Host ("TELEMETRY_EVENTS: " + $telemetryCount)
    Write-Host ("ENGINE_RECEIPTS: " + $receiptCount)
    Write-Host ("ENGINE_EVENTS: " + $eventCount)
    Write-Host ("MACHINE_PRESENT: " + $machinePresent)
    Write-Host ("DRIVES_PRESENT: " + $drivesPresent)
    Write-Host ("PROCESSES_PRESENT: " + $processesPresent)
    Write-Host ("PROCESS_ORIGINS_PRESENT: " + $processOriginsPresent)
    Write-Host ("PROCESS_COUNT: " + $processCount)
    Write-Host ("RUNTIME_ROOT: " + $RuntimeRoot)
    return
  }

  default { WT-Die ("UNKNOWN_COMMAND: " + $Command) }
}
