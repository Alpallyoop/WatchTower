# Reference producer for the live-state-surgeon -> WatchTower telemetry contract
# (docs/contracts/live-state-surgeon.md). It builds packets exactly the way
# WatchTower expects them, and exposes hooks so a test can inject one precise
# fault at a single layer. It is test support, not part of WatchTower's runtime
# API (WatchTower verifies telemetry; live-state-surgeon emits it).
#
# Build order:
#   payload/telemetry_event.json (canonical JSON + LF)
#   payload/telemetry_event.sig  (namespace per event type)
#   informational copies: signer_ed25519.pub, payload/allowed_signers, payload/trust_bundle.json
#   manifest.json                (packet.manifest.v1; files[] = every file except manifest.json,
#                                 packet_id.txt, sha256sums.txt and signatures/packet.sig)
#   signatures/packet.sig        (over manifest.json, namespace watchtower/packet)
#   packet_id.txt                (sha256 of manifest.json bytes + LF)
#   sha256sums.txt               (every file except itself, ordinal by path)

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
foreach ($name in @('Errors', 'IO', 'Json', 'Paths', 'Native')) { . (Join-Path $repoRoot ('src/WatchTower/Private/{0}.ps1' -f $name)) }

$script:ReferenceNamespaces = @{
    'watchtower.heartbeat.v1'     = 'watchtower/telemetry-heartbeat'
    'watchtower.health_report.v1' = 'watchtower/telemetry-health'
    'watchtower.policy_attest.v1' = 'watchtower/telemetry-policy'
    'watchtower.alert.v1'         = 'watchtower/telemetry-alert'
}

function New-ReferenceProducerKey {
    param([Parameter(Mandatory = $true)][string]$Directory, [string]$Name = 'producer_ed25519', [string]$Comment = 'reference-producer')
    New-WtDirectory $Directory
    $path = Join-Path $Directory $Name
    New-WtSshKey -Path $path -Comment $Comment
    return $path
}

function New-ReferenceBody {
    # A valid body for each event type (hashes computed exactly as the contract requires).
    param([Parameter(Mandatory = $true)][string]$EventType, [string]$HealthStatus = 'ok', [string]$Compliance = 'compliant', [string]$PolicyVersion = '1', [string]$AlertState = 'drift')
    $body = New-WtObject
    switch -CaseSensitive ($EventType) {
        'watchtower.heartbeat.v1' {
            $body['uptime_seconds'] = 3600
            $body['capabilities'] = @('emit', 'heartbeat')
        }
        'watchtower.health_report.v1' {
            $measurement = New-WtObject; $measurement['key'] = 'disk.free_ratio'; $measurement['value'] = '0.42'
            $posture = New-WtObject; $posture['schema'] = 'watchtower.posture.v1'; $posture['measurements'] = @($measurement)
            $posture = Copy-WtJsonValue $posture
            $body['health_status'] = $HealthStatus
            $body['signals'] = @()
            $body['posture'] = $posture
            $body['posture_hash'] = Get-WtCanonicalHash $posture
            $body['evidence_refs'] = @()
        }
        'watchtower.policy_attest.v1' {
            $policy = New-WtObject
            $policy['schema'] = 'covenantgate.effective_policy.v1'
            $policy['policy_id'] = 'baseline'
            $policy['policy_version'] = $PolicyVersion
            $policy['rules_hash'] = ('ab' * 32)
            $body['effective_group'] = 'fleet-a'
            $body['policy'] = $policy
            $body['policy_hash_claimed'] = Get-WtCanonicalHash $policy
            $body['compliance'] = $Compliance
            $body['violations'] = @()
        }
        'watchtower.alert.v1' {
            $body['alert_type'] = 'DRIFT'
            $body['state'] = $AlertState
            $body['reason_codes'] = @('POLICY_HASH_MISMATCH')
            $body['evidence'] = @()
        }
    }
    return , (Copy-WtJsonValue $body)
}

function Update-ReferenceSeal {
    # Recomputes packet_id.txt and sha256sums.txt from the current files, so a test can
    # isolate a fault in an inner layer while every outer layer stays consistent.
    param([Parameter(Mandatory = $true)][string]$Directory)
    $manifestPath = Join-Path $Directory 'manifest.json'
    Write-WtBytes -Path (Join-Path $Directory 'packet_id.txt') -Bytes (ConvertTo-WtUtf8 ((Get-WtSha256 -Path $manifestPath) + "`n"))
    $sumsPath = Join-Path $Directory 'sha256sums.txt'
    if ([System.IO.File]::Exists($sumsPath)) { [System.IO.File]::Delete($sumsPath) }
    $builder = New-Object System.Text.StringBuilder
    foreach ($file in (Get-WtTreeFile $Directory)) { [void]$builder.Append((Get-WtSha256 -Path (Join-Path $Directory $file))).Append('  ').Append($file).Append("`n") }
    Write-WtBytes -Path $sumsPath -Bytes (ConvertTo-WtUtf8 $builder.ToString())
}

function Update-ReferenceManifest {
    # Rewrites manifest.files hashes (and optionally re-signs the manifest), then reseals.
    param([Parameter(Mandatory = $true)][string]$Directory, [string]$KeyPath = '', [scriptblock]$Edit)
    $manifestPath = Join-Path $Directory 'manifest.json'
    $manifest = Read-WtJsonFile -Path $manifestPath -Object
    foreach ($entry in $manifest['files']) { $entry['sha256'] = Get-WtSha256 -Path (Join-Path $Directory ([string]$entry['path'])) }
    if ($manifest.Contains('payload') -and $manifest['payload'] -is [System.Collections.IDictionary]) {
        $manifest['payload']['event_hash'] = Get-WtSha256 -Path (Join-Path $Directory 'payload/telemetry_event.json')
    }
    if ($Edit) { & $Edit $manifest }
    Write-WtJsonFile -Path $manifestPath -Value $manifest
    if ($KeyPath) { New-WtSignature -KeyPath $KeyPath -Namespace 'watchtower/packet' -MessagePath $manifestPath -SignaturePath (Join-Path $Directory 'signatures/packet.sig') }
    Update-ReferenceSeal $Directory
}

function New-ReferenceTelemetryPacket {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$EventType,
        [string]$Principal = 'lss-reference',
        [string]$KeyId = 'lss-reference-ed25519',
        [string]$ProducerInstance = 'instance-a',
        [string]$DeviceId = '9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10',
        [string]$EventId = '',
        [string]$ProducerTime = '2026-10-13T12:00:00Z',
        [string]$CreatedTime = '',
        [long]$Seq = 1,
        [System.Collections.IDictionary]$Body,
        [string]$EventSignerKey = '',
        [string]$EventNamespace = '',
        [string]$PacketSignerKey = '',
        [string]$PacketNamespace = 'watchtower/packet',
        [scriptblock]$EditEnvelope,
        [scriptblock]$EditManifest,
        [scriptblock]$AfterBuild
    )
    if ([System.IO.Directory]::Exists($Directory)) { throw "reference packet directory exists: $Directory" }
    New-WtDirectory $Directory
    if (-not $EventId) { $EventId = 'evt-{0}-{1}' -f $Seq, $EventType.Split('.')[1] }
    if (-not $CreatedTime) { $CreatedTime = $ProducerTime }
    if (-not $Body) { $Body = New-ReferenceBody -EventType $EventType }
    $namespace = $script:ReferenceNamespaces[$EventType]
    if (-not $namespace) { $namespace = 'watchtower/telemetry-unknown' }

    $softwareRef = New-WtObject; $softwareRef['kind'] = 'build_id'; $softwareRef['value'] = 'reference-1.0.0'
    $header = New-WtObject
    $header['event_id'] = $EventId
    $header['device_id'] = $DeviceId
    $header['producer'] = $Principal
    $header['producer_instance'] = $ProducerInstance
    $header['key_id'] = $KeyId
    $header['namespace'] = $namespace
    $header['producer_time'] = $ProducerTime
    $header['seq'] = $Seq
    $header['software_ref'] = $softwareRef
    $header['prev_links'] = @()
    $envelope = New-WtObject
    $envelope['schema'] = 'watchtower.telemetry_event.v1'
    $envelope['event_type'] = $EventType
    $envelope['header'] = $header
    $envelope['body'] = $Body
    $envelope = Copy-WtJsonValue $envelope
    if ($EditEnvelope) { & $EditEnvelope $envelope }

    $eventPath = Join-Path $Directory 'payload/telemetry_event.json'
    Write-WtJsonFile -Path $eventPath -Value $envelope
    $eventKey = $(if ($EventSignerKey) { $EventSignerKey } else { $KeyPath })
    $eventNs = $(if ($EventNamespace) { $EventNamespace } else { $namespace })
    New-WtSignature -KeyPath $eventKey -Namespace $eventNs -MessagePath $eventPath -SignaturePath (Join-Path $Directory 'payload/telemetry_event.sig')

    # Informational copies (WatchTower must never trust these).
    $publicLine = (Read-WtText ($KeyPath + '.pub')).TrimEnd()
    Write-WtText -Path (Join-Path $Directory 'signer_ed25519.pub') -Text $publicLine
    Write-WtText -Path (Join-Path $Directory 'payload/allowed_signers') -Text ('{0} namespaces="{1}" {2}' -f $Principal, ((@('watchtower/packet') + @($script:ReferenceNamespaces.PSBase.Values | Sort-Object)) -join ','), (ConvertTo-WtPublicKey $publicLine))
    $informational = New-WtObject
    $informational['schema'] = 'lss.trust_bundle.v1'; $informational['principal'] = $Principal; $informational['key_id'] = $KeyId; $informational['public_key'] = $publicLine
    Write-WtJsonFile -Path (Join-Path $Directory 'payload/trust_bundle.json') -Value $informational

    $files = New-Object System.Collections.ArrayList
    foreach ($file in (Get-WtTreeFile $Directory)) {
        $entry = New-WtObject; $entry['path'] = $file; $entry['sha256'] = Get-WtSha256 -Path (Join-Path $Directory $file)
        [void]$files.Add($entry)
    }
    $descriptor = New-WtObject
    $descriptor['event_type'] = $EventType
    $descriptor['event_schema'] = 'watchtower.telemetry_event.v1'
    $descriptor['event_hash'] = Get-WtSha256 -Path $eventPath
    $manifest = New-WtObject
    $manifest['schema'] = 'packet.manifest.v1'
    $manifest['packet_kind'] = 'packet.telemetry.v1'
    $manifest['producer'] = $Principal
    $manifest['producer_instance'] = $ProducerInstance
    $manifest['created_time'] = $CreatedTime
    $manifest['payload'] = $descriptor
    $manifest['files'] = $files
    $manifest = Copy-WtJsonValue $manifest
    if ($EditManifest) { & $EditManifest $manifest }
    $manifestPath = Join-Path $Directory 'manifest.json'
    Write-WtJsonFile -Path $manifestPath -Value $manifest
    $packetKey = $(if ($PacketSignerKey) { $PacketSignerKey } else { $KeyPath })
    New-WtSignature -KeyPath $packetKey -Namespace $PacketNamespace -MessagePath $manifestPath -SignaturePath (Join-Path $Directory 'signatures/packet.sig')
    Update-ReferenceSeal $Directory
    if ($AfterBuild) { & $AfterBuild $Directory }
    return $Directory
}
