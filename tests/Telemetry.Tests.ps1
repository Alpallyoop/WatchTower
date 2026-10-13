# Stateless verification of the live-state-surgeon -> WatchTower telemetry contract
# (docs/contracts/live-state-surgeon.md): every event type, signer trust, and one test per
# fault, each injected at a single layer while every outer layer stays consistent.
. (Join-Path $PSScriptRoot 'support/TestHarness.ps1')
. (Join-Path $PSScriptRoot 'support/ReferenceProducer.ps1')
$repo = Get-WtRepoRoot
Import-Module (Join-Path $repo 'src/WatchTower/WatchTower.psd1') -Force

$work = New-WtTempDirectory 'wt_telemetry_tests'
$keys = Join-Path $work 'keys'
$producerKey = New-ReferenceProducerKey -Directory $keys -Name 'producer'
$strangerKey = New-ReferenceProducerKey -Directory $keys -Name 'stranger' -Comment 'stranger'
$producerNamespaces = @('watchtower/packet', 'watchtower/telemetry-alert', 'watchtower/telemetry-health', 'watchtower/telemetry-heartbeat', 'watchtower/telemetry-policy')

function New-TestTrustBundle {
    param([Parameter(Mandatory = $true)][string]$PublicKeyPath)
    $key = New-WtObject
    $key['key_id'] = 'lss-reference-ed25519'
    $key['alg'] = 'ssh-ed25519'
    $key['pubkey'] = ConvertTo-WtPublicKey (Read-WtText $PublicKeyPath)
    $key['namespaces'] = $producerNamespaces
    $principal = New-WtObject
    $principal['principal'] = 'lss-reference'
    $principal['keys'] = @($key)
    $bundle = New-WtObject
    $bundle['schema'] = 'neverlost.trust_bundle.v1'
    $bundle['created_utc'] = '2026-10-13T00:00:00Z'
    $bundle['principals'] = @($principal)
    return , (Copy-WtJsonValue $bundle)
}
$bundle = New-TestTrustBundle ($producerKey + '.pub')
$counter = 0
function New-CasePacket {
    param([hashtable]$Options)
    $script:counter++
    $directory = Join-Path $work ('pkt{0:000}' -f $script:counter)
    $arguments = @{ Directory = $directory; KeyPath = $producerKey; EventType = 'watchtower.heartbeat.v1' }
    foreach ($k in $Options.Keys) { $arguments[$k] = $Options[$k] }
    return New-ReferenceTelemetryPacket @arguments
}

# --- positives -------------------------------------------------------------------------
foreach ($eventType in @('watchtower.heartbeat.v1', 'watchtower.health_report.v1', 'watchtower.policy_attest.v1', 'watchtower.alert.v1')) {
    Invoke-WtTest ('accepts a signed ' + $eventType + ' packet and extracts its facts') {
        $packet = New-CasePacket @{ EventType = $eventType; Seq = 7; DeviceId = 'dev-0001' }
        $verdict = Test-WtTelemetryPacket -Path $packet -TrustBundle $bundle
        Assert-WtTrue $verdict.Valid ('{0} {1}' -f $verdict.Code, $verdict.Detail)
        Assert-WtEqual 'OK' $verdict.Code
        Assert-WtTrue $verdict.SignerVerified
        Assert-WtEqual $eventType $verdict.EventType
        Assert-WtEqual 'dev-0001' $verdict.DeviceId
        Assert-WtEqual ([long]7) $verdict.Seq
        Assert-WtEqual 'lss-reference' $verdict.Producer
        Assert-WtEqual ((Get-Content -LiteralPath (Join-Path $packet 'packet_id.txt') -Raw).Trim()) $verdict.PacketId
    }.GetNewClosure()
}

Invoke-WtTest 'verification never modifies the packet' {
    $packet = New-CasePacket @{ EventType = 'watchtower.health_report.v1' }
    $before = Get-WtTreeDigest $packet
    [void](Test-WtTelemetryPacket -Path $packet -TrustBundle $bundle)
    Assert-WtEqual $before (Get-WtTreeDigest $packet)
}

Invoke-WtTest 'the result is deterministic for identical input' {
    $packet = New-CasePacket @{ EventType = 'watchtower.policy_attest.v1' }
    $first = Test-WtTelemetryPacket -Path $packet -TrustBundle $bundle
    $second = Test-WtTelemetryPacket -Path $packet -TrustBundle $bundle
    foreach ($field in @('Valid', 'Code', 'PacketId', 'EventHash', 'EventId', 'DeviceId', 'ProducerTime', 'Seq')) { Assert-WtEqual $first.$field $second.$field $field }
}

# --- negatives: one fault per case ----------------------------------------------------------
$faults = @(
    # signer trust (the packet's own allowed_signers / trust_bundle / signer pub are never trusted)
    @('self-vouching packet signed by an unenrolled key', 'PACKET_SIG_INVALID', @{ PacketSignerKey = $strangerKey; EventSignerKey = $strangerKey }),
    @('producer principal not enrolled', 'SIGNER_NOT_TRUSTED', @{ Principal = 'stranger' }),
    @('header key_id not enrolled for the producer', 'SIGNER_NOT_TRUSTED', @{ KeyId = 'other-key' }),
    @('manifest signed under the wrong namespace', 'PACKET_SIG_INVALID', @{ PacketNamespace = 'watchtower/telemetry-heartbeat' }),
    @('event signed under another event type namespace', 'EVENT_SIG_INVALID', @{ EventNamespace = 'watchtower/telemetry-health' }),
    @('event signed by a different key than the manifest', 'EVENT_SIG_INVALID', @{ EventSignerKey = $strangerKey }),
    @('event modified after signing', 'EVENT_SIG_INVALID', @{ AfterBuild = {
                param($d)
                $path = Join-Path $d 'payload/telemetry_event.json'
                Write-WtText -Path $path -Text ((Read-WtText $path).Replace('"uptime_seconds":3600', '"uptime_seconds":3601'))
                Update-ReferenceManifest -Directory $d -KeyPath $producerKey
            }.GetNewClosure() }),
    @('placeholder (NOSIGN) event signature', 'SIG_NOT_ARMORED', @{ AfterBuild = {
                param($d)
                Write-WtText -Path (Join-Path $d 'payload/telemetry_event.sig') -Text 'NOSIGN'
                Update-ReferenceManifest -Directory $d -KeyPath $producerKey
            }.GetNewClosure() }),
    @('missing manifest signature', 'MISSING_PACKET_SIGNATURE', @{ AfterBuild = { param($d) [System.IO.File]::Delete((Join-Path $d 'signatures/packet.sig')); Update-ReferenceSeal $d } }),

    # outer packet law surfaces first
    @('payload tampered without resealing', 'SHA256_MISMATCH', @{ AfterBuild = { param($d) Add-Content -LiteralPath (Join-Path $d 'payload/telemetry_event.json') -Value 'x' -NoNewline } }),

    # manifest
    @('manifest schema', 'MANIFEST_SCHEMA', @{ EditManifest = { param($m) $m['schema'] = 'packet.manifest.v2' } }),
    @('packet kind', 'PACKET_KIND_UNSUPPORTED', @{ EditManifest = { param($m) $m['packet_kind'] = 'packet.attest.v1' } }),
    @('event type outside the contract (posture)', 'EVENT_TYPE_UNSUPPORTED', @{ EventType = 'watchtower.posture.v1'; Body = (New-WtObject) }),
    @('event type differing only in case', 'EVENT_TYPE_UNSUPPORTED', @{ EditManifest = { param($m) $m['payload']['event_type'] = 'WATCHTOWER.HEARTBEAT.V1' } }),
    @('event schema in the manifest', 'EVENT_SCHEMA_UNSUPPORTED', @{ EditManifest = { param($m) $m['payload']['event_schema'] = 'watchtower.telemetry_event.v0' } }),
    @('manifest event_hash wrong', 'EVENT_HASH_MISMATCH', @{ EditManifest = { param($m) $m['payload']['event_hash'] = ('0' * 64) } }),
    @('manifest lists its own signature', 'MANIFEST_LISTS_OWN_SIGNATURE', @{ EditManifest = { param($m) $e = New-WtObject; $e['path'] = 'signatures/packet.sig'; $e['sha256'] = ('0' * 64); [void]$m['files'].Add($e) } }),
    @('manifest omits a payload file', 'MANIFEST_FILES_INCOMPLETE', @{ EditManifest = { param($m) $m['files'].RemoveAt(0) } }),
    @('manifest file hash wrong', 'MANIFEST_FILE_HASH_MISMATCH', @{ EditManifest = { param($m) $m['files'][0]['sha256'] = ('0' * 64) } }),
    @('manifest created_time format', 'TIME_FORMAT', @{ CreatedTime = '2026-10-13 12:00:00' }),

    # event envelope
    @('envelope schema', 'EVENT_SCHEMA_UNSUPPORTED', @{ EditEnvelope = { param($e) $e['schema'] = 'watchtower.telemetry_event.v2' } }),
    @('envelope event_type disagrees with the manifest', 'EVENT_TYPE_MISMATCH', @{ EditEnvelope = { param($e) $e['event_type'] = 'watchtower.alert.v1' } }),
    @('header producer disagrees with the manifest', 'PRODUCER_MISMATCH', @{ EditEnvelope = { param($e) $e['header']['producer'] = 'someone-else' } }),
    @('header producer_instance disagrees with the manifest', 'PRODUCER_INSTANCE_MISMATCH', @{ EditEnvelope = { param($e) $e['header']['producer_instance'] = 'instance-b' } }),
    @('header namespace is not the one for the event type', 'NAMESPACE_MISMATCH', @{ EditEnvelope = { param($e) $e['header']['namespace'] = 'watchtower/telemetry-health' } }),
    @('header device_id with unsafe characters', 'HEADER_IDENTIFIER_FORMAT', @{ DeviceId = 'dev 1/../x' }),
    @('header producer_time format', 'TIME_FORMAT', @{ ProducerTime = '2026-10-13T12:00:00.5Z' }),
    @('negative sequence number', 'HEADER_SEQ_NEGATIVE', @{ Seq = -1 }),
    @('missing header field', 'FIELD_MISSING', @{ EditEnvelope = { param($e) $e['header'].Remove('event_id') } }),

    # strict JSON inside the event
    @('float in the event', 'EVENT_INVALID', @{ AfterBuild = {
                param($d)
                $path = Join-Path $d 'payload/telemetry_event.json'
                Write-WtText -Path $path -Text ((Read-WtText $path).Replace('"uptime_seconds":3600', '"uptime_seconds":3600.5'))
                Update-ReferenceManifest -Directory $d -KeyPath $producerKey
            }.GetNewClosure() }),
    @('duplicate key in the event', 'EVENT_INVALID', @{ AfterBuild = {
                param($d)
                $path = Join-Path $d 'payload/telemetry_event.json'
                Write-WtText -Path $path -Text ((Read-WtText $path).Replace('"uptime_seconds":3600', '"uptime_seconds":3600,"uptime_seconds":1'))
                Update-ReferenceManifest -Directory $d -KeyPath $producerKey
            }.GetNewClosure() }),
    @('UTF-8 BOM in the event', 'EVENT_INVALID', @{ AfterBuild = {
                param($d)
                $path = Join-Path $d 'payload/telemetry_event.json'
                Write-WtBytes -Path $path -Bytes ([byte[]](0xEF, 0xBB, 0xBF) + (Read-WtBytes $path))
                Update-ReferenceManifest -Directory $d -KeyPath $producerKey
            }.GetNewClosure() }),

    # body rules (recomputed, never trusted)
    @('heartbeat without uptime_seconds', 'FIELD_MISSING', @{ EditEnvelope = { param($e) $e['body'].Remove('uptime_seconds') } }),
    @('health_report posture_hash not recomputable', 'POSTURE_HASH_MISMATCH', @{ EventType = 'watchtower.health_report.v1'; EditEnvelope = { param($e) $e['body']['posture_hash'] = ('1' * 64) } }),
    @('health_report status outside the enum', 'BODY_VALUE', @{ EventType = 'watchtower.health_report.v1'; Body = (New-ReferenceBody -EventType 'watchtower.health_report.v1' -HealthStatus 'meh') }),
    @('policy_attest policy_hash_claimed not recomputable', 'POLICY_HASH_MISMATCH', @{ EventType = 'watchtower.policy_attest.v1'; EditEnvelope = { param($e) $e['body']['policy_hash_claimed'] = ('2' * 64) } }),
    @('policy_attest compliance outside the enum', 'BODY_VALUE', @{ EventType = 'watchtower.policy_attest.v1'; Body = (New-ReferenceBody -EventType 'watchtower.policy_attest.v1' -Compliance 'maybe') }),
    @('policy_attest policy schema', 'BODY_VALUE', @{ EventType = 'watchtower.policy_attest.v1'; EditEnvelope = { param($e) $e['body']['policy']['schema'] = 'other.policy.v1' } }),
    @('alert state outside the enum', 'BODY_VALUE', @{ EventType = 'watchtower.alert.v1'; Body = (New-ReferenceBody -EventType 'watchtower.alert.v1' -AlertState 'exploded') })
)
foreach ($fault in $faults) {
    $label = $fault[0]; $expected = $fault[1]; $options = $fault[2]
    Invoke-WtTest ('rejects: ' + $label + ' -> ' + $expected) {
        $packet = New-CasePacket $options
        $before = Get-WtTreeDigest $packet
        $verdict = Test-WtTelemetryPacket -Path $packet -TrustBundle $bundle
        Assert-WtTrue (-not $verdict.Valid) 'packet was accepted'
        Assert-WtEqual $expected $verdict.Code $verdict.Detail
        Assert-WtEqual $before (Get-WtTreeDigest $packet) 'packet was modified'
    }.GetNewClosure()
}

Remove-WtTree $work
Complete-WtTestSuite 'WATCHTOWER_TELEMETRY_TESTS'
