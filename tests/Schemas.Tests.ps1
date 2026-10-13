# Schema conformance: every schema WatchTower publishes is checked statically, and every
# document WatchTower emits (and every inbound shape it accepts) is validated against its
# schema. The validator fails on any keyword it does not implement, so a schema cannot carry
# a constraint that nothing checks.
. (Join-Path $PSScriptRoot 'support/TestHarness.ps1')
. (Join-Path $PSScriptRoot 'support/ReferenceProducer.ps1')
. (Join-Path $PSScriptRoot 'support/SchemaValidator.ps1')
$repo = Get-WtRepoRoot
$module = Import-Module (Join-Path $repo 'src/WatchTower/WatchTower.psd1') -Force -PassThru
$schemas = Join-Path $repo 'schemas'

function Get-SchemaPath { param([string]$Name) return (Join-Path $schemas ($Name + '.json')) }
function Invoke-Private { param([scriptblock]$Script, [object[]]$Arguments = @()) return & $module $Script @Arguments }
function Get-ChainRows {
    param([string]$Path, [string]$HashField, [string]$PrevField)
    return , (Invoke-Private { param($p, $h, $v) (Open-WtHashChain -Path $p -HashField $h -PrevField $v).Rows } @($Path, $HashField, $PrevField))
}

# Schemas that WatchTower v2 owns (emits or accepts). The six legacy v1 schemas
# (attestation_record_v1, device_identity_v1, ledger_event_v1, observation_set_v1,
# watchtower.device.v1, watchtower.device_event.v1) are not emitted by the v2 module and are
# kept unchanged for the record; see docs/canonical/CURRENT_STATE.md.
$owned = @(
    'packet.manifest.v1', 'watchtower.telemetry_event.v1', 'watchtower.posture.v1',
    'watchtower.telemetry.receipt.v1', 'watchtower.alert.v1', 'watchtower.checkpoint.v1', 'watchtower.device_pledge.v1',
    'watchtower.receipt_packet.v1', 'watchtower.receipt_artifact.v1',
    'watchtower.heartbeat.v1', 'watchtower.health_report.v1', 'watchtower.policy_attest.v1',
    'watchtower.evidence_index.v1', 'watchtower.settings.v1', 'watchtower.ingest_run.v1',
    'watchtower.doctor_report.v1', 'watchtower.quarantine_note.v1', 'watchtower.test_run.v1')

# --- the schemas themselves -----------------------------------------------------------------
Invoke-WtTest 'schemas: every owned schema is canonical-parseable and uses only supported keywords' {
    foreach ($name in $owned) {
        $schema = Read-WtJsonFile -Path (Get-SchemaPath $name) -Object
        try { Assert-SchemaSupported $schema }
        catch { throw ('{0}: {1}' -f $name, $_.Exception.Message) }
    }
}
Invoke-WtTest 'schemas: $id matches the file name and draft 2020-12 is declared' {
    foreach ($name in $owned) {
        $schema = Read-WtJsonFile -Path (Get-SchemaPath $name) -Object
        Assert-WtEqual 'https://json-schema.org/draft/2020-12/schema' $schema['$schema'] $name
        Assert-WtEqual ('https://github.com/ScrappyHub/WatchTower/schemas/' + $name + '.json') $schema['$id'] $name
        Assert-WtTrue ([string]$schema['title']).Length -gt 0 ($name + ' has no title')
    }
}
Invoke-WtTest 'schemas: every schema file is UTF-8 without BOM, LF-only and ends with a newline' {
    foreach ($file in [System.IO.Directory]::GetFiles($schemas, '*.json')) {
        $bytes = [System.IO.File]::ReadAllBytes($file)
        $name = [System.IO.Path]::GetFileName($file)
        Assert-WtTrue (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) ($name + ' has a BOM')
        Assert-WtTrue ([Array]::IndexOf($bytes, [byte]13) -lt 0) ($name + ' has CR')
        # Legacy v1 files predate the final-newline rule and are kept byte-for-byte.
        if ($owned -ccontains $name.Substring(0, $name.Length - 5)) { Assert-WtEqual ([byte]10) $bytes[$bytes.Length - 1] ($name + ' does not end with LF') }
        [void](Read-WtJsonFile -Path $file -Object)
    }
}
Invoke-WtTest 'validator: refuses keywords it does not implement and unresolved references' {
    $format = New-WtObject; $format['type'] = 'string'; $format['format'] = 'date-time'
    $threw = $false; try { Assert-SchemaSupported $format } catch { $threw = $_.Exception.Message -like 'SCHEMA_KEYWORD_UNSUPPORTED*' }
    Assert-WtTrue $threw 'format must be refused'
    $nested = ConvertFrom-WtJson '{"type":"object","properties":{"a":{"if":{"const":1},"then":{"minProperties":1}}}}'
    $threw = $false; try { Assert-SchemaSupported $nested } catch { $threw = $_.Exception.Message -like 'SCHEMA_KEYWORD_UNSUPPORTED*' }
    Assert-WtTrue $threw 'a keyword hidden in a then-branch must be found'
    $ref = ConvertFrom-WtJson '{"$ref":"#/$defs/missing"}'
    $threw = $false; try { Assert-SchemaSupported $ref } catch { $threw = $_.Exception.Message -like 'SCHEMA_REF_UNRESOLVED*' }
    Assert-WtTrue $threw 'an unresolved $ref must be refused'
}
Invoke-WtTest 'validator: enforces type, const, enum, pattern, required, additionalProperties and if/then' {
    $schema = ConvertFrom-WtJson ('{"type":"object","required":["a"],"additionalProperties":false,"properties":{"a":{"enum":["x","y"]},"b":{"type":"integer","minimum":0},' +
        '"c":{"type":"string","pattern":"^[0-9a-f]{4}$"},"d":{"const":true}},"if":{"properties":{"a":{"const":"y"}}},"then":{"required":["b"]}}')
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ('wt_schema_probe_' + [guid]::NewGuid().ToString('N') + '.json')
    Write-WtJsonFile -Path $path -Value $schema
    try {
        Assert-WtEqual 0 (Get-SchemaErrors -SchemaPath $path -Value (ConvertFrom-WtJson '{"a":"x","c":"00ff","d":true}')).Length
        foreach ($bad in @('{"c":"00ff"}', '{"a":"z"}', '{"a":"x","b":-1}', '{"a":"x","c":"00FF"}', '{"a":"x","d":false}', '{"a":"x","e":1}', '{"a":"y"}', '{"a":"x","b":"1"}')) {
            Assert-WtTrue ((Get-SchemaErrors -SchemaPath $path -Value (ConvertFrom-WtJson $bad)).Length -gt 0) ('accepted ' + $bad)
        }
    }
    finally { [System.IO.File]::Delete($path) }
}

# --- a complete node run: everything WatchTower writes ---------------------------------------
$work = New-WtTempDirectory 'wt_schema_tests'
$producerKey = New-ReferenceProducerKey -Directory (Join-Path $work 'keys') -Name 'producer'
[void](New-ReferenceProducerKey -Directory (Join-Path $work 'keys') -Name 'stranger' -Comment 'stranger')
$root = Join-Path $work 'node'
New-WtDirectory $root
[void](Initialize-WtTrust -Root $root -CreatedUtc '2026-10-13T12:00:00Z')
[void](Register-WtProducer -Root $root -Principal 'lss-reference' -KeyId 'lss-reference-ed25519' -PublicKey ($producerKey + '.pub'))
$policyHash = (New-ReferenceBody -EventType 'watchtower.policy_attest.v1')['policy_hash_claimed']
$settings = ConvertFrom-WtJson ('{"schema":"watchtower.settings.v1","max_future_skew_seconds":300,' +
    '"service_bindings":[{"service_id":"live-state-surgeon","producer":"lss-reference","producer_instance":"instance-a"}],' +
    '"policy_pins":[{"effective_group":"fleet-a","expected_policy_hash":"' + $policyHash + '"}]}')
Write-WtJsonFile -Path (Join-Path $root 'config/watchtower.settings.json') -Value $settings
$inbox = Join-Path $root 'packets/inbox'
$reference = New-Object System.Collections.Generic.List[string]
$seq = 0
foreach ($type in @('watchtower.heartbeat.v1', 'watchtower.health_report.v1', 'watchtower.policy_attest.v1', 'watchtower.alert.v1')) {
    $seq++
    $dir = Join-Path $inbox ('a{0:00}-{1}' -f $seq, $type.Split('.')[1])
    [void](New-ReferenceTelemetryPacket -Directory $dir -KeyPath $producerKey -EventType $type -Seq $seq -ProducerTime ('2026-10-13T12:0{0}:00Z' -f $seq))
    $reference.Add($dir)
}
[void](New-ReferenceTelemetryPacket -Directory (Join-Path $inbox 'b01-forged') -KeyPath $producerKey -EventType 'watchtower.heartbeat.v1' -Seq 9 -EventId 'evt-forged' -PacketSignerKey (Join-Path $work 'keys/stranger') -EventSignerKey (Join-Path $work 'keys/stranger'))
[void](New-ReferenceTelemetryPacket -Directory (Join-Path $inbox 'b02-regression') -KeyPath $producerKey -EventType 'watchtower.heartbeat.v1' -Seq 2 -EventId 'evt-late' -ProducerTime '2026-10-13T12:08:00Z')
# Inbound shapes are captured before ingest moves the packets.
$inboundEvents = @($reference | ForEach-Object { Read-WtJsonFile -Path (Join-Path $_ 'payload/telemetry_event.json') -Object })
$inboundManifests = @($reference | ForEach-Object { Read-WtJsonFile -Path (Join-Path $_ 'manifest.json') -Object })
$run = Invoke-WtIngest -Root $root -VerificationTime '2026-10-13T12:10:00Z'
$doctor = Invoke-WtDoctor -Root $root -VerificationTime '2026-10-13T12:20:00Z' -Publish

Invoke-WtTest 'scenario: the run produced accepted and rejected packets, a seal and a healthy doctor' {
    Assert-WtEqual 4 $run.Accepted
    Assert-WtEqual 2 $run.Rejected
    Assert-WtTrue (Test-WtHex64 $run.OutboxPacketId)
    Assert-WtTrue $doctor.HealthOk
}
Invoke-WtTest 'inbound: reference events, posture and manifests match their schemas' {
    foreach ($event in $inboundEvents) {
        Assert-MatchesSchema (Get-SchemaPath 'watchtower.telemetry_event.v1') $event ('event ' + $event['event_type'])
        if ($event['event_type'] -ceq 'watchtower.health_report.v1') { Assert-MatchesSchema (Get-SchemaPath 'watchtower.posture.v1') $event['body']['posture'] 'posture' }
    }
    foreach ($manifest in $inboundManifests) { Assert-MatchesSchema (Get-SchemaPath 'packet.manifest.v1') $manifest 'reference manifest' }
}
Invoke-WtTest 'inbound: the real live-state-surgeon event matches; its manifest shape too (the own-signature defect is a verifier rule)' {
    $fixture = Join-Path $repo 'tests/fixtures/interop/live-state-surgeon/pkt-hb-node-ok'
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.telemetry_event.v1') (Read-WtJsonFile -Path (Join-Path $fixture 'payload/telemetry_event.json') -Object) 'LSS event'
    Assert-MatchesSchema (Get-SchemaPath 'packet.manifest.v1') (Read-WtJsonFile -Path (Join-Path $fixture 'manifest.json') -Object) 'LSS manifest'
    Assert-WtEqual 'MANIFEST_LISTS_OWN_SIGNATURE' (Test-WtTelemetryPacket -Path $fixture -TrustBundle (Read-WtJsonFile -Path (Join-Path $root 'proofs/trust/neverlost/trust_bundle.json') -Object)).Code
}
Invoke-WtTest 'receipts: every ok and reject row matches watchtower.telemetry.receipt.v1' {
    $rows = Get-ChainRows (Join-Path $root 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson') 'receipt_hash' 'prev_receipt_hash'
    Assert-WtEqual 6 $rows.Count
    Assert-WtEqual 'ok,reject' ((@($rows | ForEach-Object { $_['verify_result'] }) | Sort-Object -Unique) -join ',')
    foreach ($row in $rows) { Assert-MatchesSchema (Get-SchemaPath 'watchtower.telemetry.receipt.v1') $row ('receipt ' + $row['packet_ref']) }
}
Invoke-WtTest 'ledgers: alert, checkpoint and pledge rows match their schemas' {
    $alerts = Get-ChainRows (Join-Path $root 'proofs/alerts/watchtower.alert.v1.ndjson') 'alert_hash' 'prev_alert_hash'
    Assert-WtTrue ($alerts.Count -ge 2) 'expected alerts'
    foreach ($row in $alerts) { Assert-MatchesSchema (Get-SchemaPath 'watchtower.alert.v1') $row ('alert ' + $row['alert_type']) }
    foreach ($row in (Get-ChainRows (Join-Path $root 'proofs/receipts/watchtower.checkpoint.v1.ndjson') 'checkpoint_hash' 'prev_checkpoint_hash')) { Assert-MatchesSchema (Get-SchemaPath 'watchtower.checkpoint.v1') $row 'checkpoint' }
    foreach ($row in (Get-ChainRows (Join-Path $root 'proofs/pledges/watchtower.device_pledge.v1.ndjson') 'pledge_hash' 'prev_pledge_hash')) { Assert-MatchesSchema (Get-SchemaPath 'watchtower.device_pledge.v1') $row 'pledge' }
}
Invoke-WtTest 'outbox: the NFL packet manifest and payload/receipt.json match their schemas' {
    $packet = Join-Path $root ('packets/outbox/' + $run.OutboxPacketId)
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.receipt_packet.v1') (Read-WtJsonFile -Path (Join-Path $packet 'manifest.json') -Object) 'outbox manifest'
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.receipt_artifact.v1') (Read-WtJsonFile -Path (Join-Path $packet 'payload/receipt.json') -Object) 'receipt.json'
}
Invoke-WtTest 'evidence: device documents and Constellation health facets match their schemas' {
    $device = Join-Path $root 'runtime/devices/9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10'
    foreach ($kind in @('heartbeat', 'health_report', 'policy_attest')) {
        Assert-MatchesSchema (Get-SchemaPath ('watchtower.' + $kind + '.v1')) (Read-WtJsonFile -Path (Join-Path $device ($kind + '.json')) -Object) ('device ' + $kind)
    }
    $facets = @([System.IO.Directory]::GetFiles((Join-Path $root 'runtime/services'), 'health_report*.json', [System.IO.SearchOption]::AllDirectories))
    Assert-WtEqual 2 $facets.Count 'live-state-surgeon and watchtower'
    foreach ($file in $facets) { Assert-MatchesSchema (Get-SchemaPath 'watchtower.health_report.v1') (Read-WtJsonFile -Path $file -Object) $file.Substring($root.Length) }
}
Invoke-WtTest 'records: settings, last ingest, evidence index, doctor report and quarantine notes match their schemas' {
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.settings.v1') (Read-WtJsonFile -Path (Join-Path $root 'config/watchtower.settings.json') -Object) 'settings'
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.settings.v1') (Invoke-Private { Get-WtDefaultSettings }) 'default settings'
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.ingest_run.v1') (Read-WtJsonFile -Path (Join-Path $root 'runtime/last_ingest.json') -Object) 'last_ingest'
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.evidence_index.v1') (Read-WtJsonFile -Path (Export-WtEvidenceIndex -Root $root) -Object) 'evidence index (re-exported)'
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.evidence_index.v1') (Read-WtJsonFile -Path (Join-Path $root 'runtime/evidence_index.json') -Object) 'evidence index (file)'
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.doctor_report.v1') (Read-WtJsonFile -Path (Join-Path $root 'runtime/doctor_report.json') -Object) 'doctor report'
    $notes = @([System.IO.Directory]::GetFiles((Join-Path $root 'packets/quarantine'), '*.rejection.json'))
    Assert-WtEqual 2 $notes.Count
    foreach ($note in $notes) { Assert-MatchesSchema (Get-SchemaPath 'watchtower.quarantine_note.v1') (Read-WtJsonFile -Path $note -Object) ([System.IO.Path]::GetFileName($note)) }
}
Invoke-WtTest 'records: the shipped example settings file is valid and loads' {
    $example = Join-Path $repo 'config/watchtower.settings.example.json'
    Assert-MatchesSchema (Get-SchemaPath 'watchtower.settings.v1') (Read-WtJsonFile -Path $example -Object) 'example settings'
    $probe = Join-Path $work 'example-node'
    New-WtDirectory (Join-Path $probe 'config')
    Copy-Item -LiteralPath $example -Destination (Join-Path $probe 'config/watchtower.settings.json')
    [void](Invoke-Private { param($r) Read-WtSettings -Layout (Get-WtLayout -Root $r) } @($probe))
}
Invoke-WtTest 'negative: schemas reject drifted documents' {
    $rows = Get-ChainRows (Join-Path $root 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson') 'receipt_hash' 'prev_receipt_hash'
    $mutations = @(
        @{ Name = 'verify_result case'; Edit = { param($r) $r['verify_result'] = 'OK' } },
        @{ Name = 'missing seq'; Edit = { param($r) [void]$r.Remove('seq') } },
        @{ Name = 'unknown field'; Edit = { param($r) $r['note'] = 'x' } },
        @{ Name = 'non-hex hash'; Edit = { param($r) $r['receipt_hash'] = 'Z' * 64 } },
        @{ Name = 'ok row with a failure code'; Edit = { param($r) $r['fail_reason']['code'] = 'PACKET_SIG_INVALID' } },
        @{ Name = 'ok row quarantined'; Edit = { param($r) $r['disposition'] = 'quarantined' } },
        @{ Name = 'ok row with an unverified signer'; Edit = { param($r) $r['signer_verified'] = $false } },
        @{ Name = 'reject row without a code'; Edit = { param($r) $r['verify_result'] = 'reject'; $r['disposition'] = 'quarantined' } })
    foreach ($mutation in $mutations) {
        $copy = Copy-WtJsonValue $rows[0]
        & $mutation.Edit $copy
        Assert-WtTrue ((Get-SchemaErrors -SchemaPath (Get-SchemaPath 'watchtower.telemetry.receipt.v1') -Value $copy).Length -gt 0) ('accepted: ' + $mutation.Name)
    }
    $facet = Read-WtJsonFile -Path (@([System.IO.Directory]::GetFiles((Join-Path $root 'runtime/services/live-state-surgeon'), 'health_report*.json'))[0]) -Object
    $facet['health_ok'] = 'true'
    Assert-WtTrue ((Get-SchemaErrors -SchemaPath (Get-SchemaPath 'watchtower.health_report.v1') -Value $facet).Length -gt 0) 'health_ok as a string'
    $event = Copy-WtJsonValue $inboundEvents[0]
    $event['header']['seq'] = -1
    Assert-WtTrue ((Get-SchemaErrors -SchemaPath (Get-SchemaPath 'watchtower.telemetry_event.v1') -Value $event).Length -gt 0) 'negative seq'
}

Remove-WtTree $work
Complete-WtTestSuite 'WATCHTOWER_SCHEMAS_TESTS'
