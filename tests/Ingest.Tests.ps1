# End-to-end: trust bootstrap, producer enrollment, inbox ingest, routing, receipts,
# published evidence, alerts, checkpoint seal, NFL outbox packet, device pledge, ledger
# re-verification, determinism across independent nodes, and fail-closed tamper handling.
. (Join-Path $PSScriptRoot 'support/TestHarness.ps1')
. (Join-Path $PSScriptRoot 'support/ReferenceProducer.ps1')
$repo = Get-WtRepoRoot
$module = Import-Module (Join-Path $repo 'src/WatchTower/WatchTower.psd1') -Force -PassThru

$work = New-WtTempDirectory 'wt_ingest_tests'
$producerKey = New-ReferenceProducerKey -Directory (Join-Path $work 'keys') -Name 'producer'
$T0 = '2026-10-13T12:00:00Z'
$RUN1 = '2026-10-13T12:05:00Z'
$RUN2 = '2026-10-13T13:05:00Z'
$policyHash = (New-ReferenceBody -EventType 'watchtower.policy_attest.v1')['policy_hash_claimed']

function Invoke-Private {
    # Runs a script block inside the module scope (private helpers).
    param([scriptblock]$Script, [object[]]$Arguments = @())
    return & $module $Script @Arguments
}

function New-StateRoot {
    param([string]$Name, [string]$PinnedPolicyHash = $policyHash)
    $root = Join-Path $work $Name
    New-WtDirectory $root
    [void](Initialize-WtTrust -Root $root -CreatedUtc $T0)
    [void](Register-WtProducer -Root $root -Principal 'lss-reference' -KeyId 'lss-reference-ed25519' -PublicKey ($producerKey + '.pub'))
    $binding = New-WtObject; $binding['service_id'] = 'live-state-surgeon'; $binding['producer'] = 'lss-reference'; $binding['producer_instance'] = 'instance-a'
    $pin = New-WtObject; $pin['effective_group'] = 'fleet-a'; $pin['expected_policy_hash'] = $PinnedPolicyHash
    $settings = New-WtObject
    $settings['schema'] = 'watchtower.settings.v1'
    $settings['max_future_skew_seconds'] = 300
    $settings['service_bindings'] = @($binding)
    $settings['policy_pins'] = @($pin)
    Write-WtJsonFile -Path (Join-Path $root 'config/watchtower.settings.json') -Value $settings
    return $root
}

function Add-InboxPacket {
    param([string]$Root, [string]$Name, [hashtable]$Options)
    $arguments = @{ Directory = (Join-Path $Root ('packets/inbox/' + $Name)); KeyPath = $producerKey; EventType = 'watchtower.heartbeat.v1' }
    foreach ($k in $Options.Keys) { $arguments[$k] = $Options[$k] }
    return New-ReferenceTelemetryPacket @arguments
}

function Get-ReceiptRows {
    param([string]$Root)
    return , (Invoke-Private { param($p) (Open-WtHashChain -Path $p -HashField 'receipt_hash' -PrevField 'prev_receipt_hash').Rows } @((Join-Path $Root 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson')))
}

function Get-AlertRows {
    param([string]$Root)
    return , (Invoke-Private { param($p) (Open-WtHashChain -Path $p -HashField 'alert_hash' -PrevField 'prev_alert_hash').Rows } @((Join-Path $Root 'proofs/alerts/watchtower.alert.v1.ndjson')))
}

function Test-EvidenceSignature {
    # Published documents carry a sibling <file>.sig; pass -Signature for any other location.
    param([string]$Root, [string]$Path, [string]$Namespace = 'watchtower', [string]$Signature = '')
    if (-not $Signature) { $Signature = $Path + '.sig' }
    $bundle = Read-WtJsonFile -Path (Join-Path $Root 'proofs/trust/neverlost/trust_bundle.json') -Object
    return Invoke-Private { param($b, $n, $s, $m) Test-WtAuthoritySignature -Bundle $b -Namespace $n -SignaturePath $s -MessagePath $m } @($bundle, $Namespace, $Signature, $Path)
}

function Add-ScenarioPackets {
    # The run-1 inbox: four valid event types, one in-progress drop and five rejections.
    param([string]$Root)
    [void](Add-InboxPacket $Root 'a01-heartbeat' @{ Seq = 1; ProducerTime = '2026-10-13T12:00:00Z' })
    [void](Add-InboxPacket $Root 'a02-health' @{ EventType = 'watchtower.health_report.v1'; Seq = 2; ProducerTime = '2026-10-13T12:01:00Z' })
    [void](Add-InboxPacket $Root 'a03-policy' @{ EventType = 'watchtower.policy_attest.v1'; Seq = 3; ProducerTime = '2026-10-13T12:02:00Z' })
    [void](Add-InboxPacket $Root 'a04-alert' @{ EventType = 'watchtower.alert.v1'; Seq = 4; ProducerTime = '2026-10-13T12:03:00Z' })
    [void](Add-InboxPacket $Root 'b01-seq-regression' @{ Seq = 2; EventId = 'evt-late'; ProducerTime = '2026-10-13T12:04:00Z' })
    [void](Add-InboxPacket $Root 'b02-future' @{ Seq = 9; EventId = 'evt-future'; ProducerTime = '2026-10-13T13:00:00Z' })
    [void](Add-InboxPacket $Root 'b03-unverified' @{ Seq = 10; EventId = 'evt-forged'; DeviceId = 'victim-device'; PacketSignerKey = (Join-Path $work 'keys/stranger'); EventSignerKey = (Join-Path $work 'keys/stranger') })
    Copy-WtTree -Source (Join-Path $Root 'packets/inbox/a01-heartbeat') -Destination (Join-Path $Root 'packets/inbox/b04-duplicate')
    [void](Add-InboxPacket $Root 'b05-not-a-packet' @{ AfterBuild = { param($d) [System.IO.File]::Delete((Join-Path $d 'manifest.json')) } })
    [void](Add-InboxPacket $Root '_in-progress' @{ Seq = 11; EventId = 'evt-partial' })
}

[void](New-ReferenceProducerKey -Directory (Join-Path $work 'keys') -Name 'stranger' -Comment 'stranger')

# --- trust bootstrap and enrollment ------------------------------------------------------
$trustRoot = Join-Path $work 'trust'
New-WtDirectory $trustRoot
Invoke-WtTest 'trust: initialise creates the authority key and a NeverLost bundle' {
    $result = Initialize-WtTrust -Root $trustRoot -CreatedUtc $T0
    Assert-WtTrue $result.CreatedKey
    Assert-WtEqual 'single-tenant/watchtower_authority/authority/watchtower' $result.Principal
    $bundle = Read-WtJsonFile -Path $result.TrustBundle -Object -Canonical
    Assert-WtEqual 'neverlost.trust_bundle.v1' $bundle['schema']
    Assert-WtEqual 'nfl/ingest-receipt,packet/envelope,watchtower,watchtower/device-pledge' (@($bundle['principals'][0]['keys'][0]['namespaces']) -join ',')
    Assert-WtTrue (Get-WtTrust -Root $trustRoot).AllowedSignersDerived
}
Invoke-WtTest 'trust: initialise is idempotent and never rotates silently' {
    $again = Initialize-WtTrust -Root $trustRoot -CreatedUtc $RUN1
    Assert-WtTrue (-not $again.CreatedKey)
    $bundlePath = Join-Path $trustRoot 'proofs/trust/neverlost/trust_bundle.json'
    $saved = Read-WtText $bundlePath
    $bundle = Read-WtJsonFile -Path $bundlePath -Object
    $bundle['principals'][0]['keys'][0]['pubkey'] = ConvertTo-WtPublicKey (Read-WtText ($producerKey + '.pub'))
    Write-WtJsonFile -Path $bundlePath -Value $bundle
    try { Assert-WtThrowsCode 'TRUST_AUTHORITY_KEY_MISMATCH' { Initialize-WtTrust -Root $trustRoot -CreatedUtc $RUN1 } }
    finally { Write-WtText -Path $bundlePath -Text $saved }
}
Invoke-WtTest 'trust: enroll a producer; identical re-enrollment is a no-op' {
    Assert-WtTrue (Register-WtProducer -Root $trustRoot -Principal 'lss-reference' -KeyId 'lss-reference-ed25519' -PublicKey ($producerKey + '.pub')).Changed
    Assert-WtTrue (-not (Register-WtProducer -Root $trustRoot -Principal 'lss-reference' -KeyId 'lss-reference-ed25519' -PublicKey ($producerKey + '.pub')).Changed)
    Assert-WtTrue (Get-WtTrust -Root $trustRoot).AllowedSignersDerived
}
Invoke-WtTest 'trust: enrollment conflicts, authority impersonation and test keys are refused' {
    Assert-WtThrowsCode 'TRUST_PRODUCER_CONFLICT' { Register-WtProducer -Root $trustRoot -Principal 'lss-reference' -KeyId 'lss-reference-ed25519' -PublicKey (Join-Path $work 'keys/stranger.pub') }
    Assert-WtThrowsCode 'TRUST_PRODUCER_IS_AUTHORITY' { Register-WtProducer -Root $trustRoot -Principal 'single-tenant/watchtower_authority/authority/watchtower' -KeyId 'x' -PublicKey (Join-Path $work 'keys/stranger.pub') }
    $testKey = New-ReferenceProducerKey -Directory (Join-Path $work 'keys') -Name 'testonly' -Comment 'TEST_ONLY reference key'
    Assert-WtThrowsCode 'TRUST_TEST_KEY_REFUSED' { Register-WtProducer -Root $trustRoot -Principal 'lab' -KeyId 'lab-1' -PublicKey ($testKey + '.pub') }
    Assert-WtTrue (Register-WtProducer -Root $trustRoot -Principal 'lab' -KeyId 'lab-1' -PublicKey ($testKey + '.pub') -AllowTestKey).Changed
}

# --- run 1 -----------------------------------------------------------------------------------
$rootA = New-StateRoot 'nodeA'
Add-ScenarioPackets $rootA
$rootB = Join-Path $work 'nodeB'
Copy-WtTree -Source $rootA -Destination $rootB      # identical node state, for determinism
$inboxDigest = Get-WtTreeDigest (Join-Path $rootA 'packets/inbox/a02-health')
$summary = Invoke-WtIngest -Root $rootA -VerificationTime $RUN1

$expected = [ordered]@{
    'a01-heartbeat' = 'OK'; 'a02-health' = 'OK'; 'a03-policy' = 'OK'; 'a04-alert' = 'OK'
    'b01-seq-regression' = 'SEQUENCE_REGRESSION'; 'b02-future' = 'FUTURE_TIMESTAMP'; 'b03-unverified' = 'PACKET_SIG_INVALID'
    'b04-duplicate' = 'DUPLICATE_PACKET'; 'b05-not-a-packet' = 'MISSING_MANIFEST'
}
Invoke-WtTest 'ingest: processes every packet once, in ordinal order, and skips in-progress drops' {
    Assert-WtEqual 9 $summary.Processed
    Assert-WtEqual 4 $summary.Accepted
    Assert-WtEqual 5 $summary.Rejected
    Assert-WtEqual '_in-progress' ($summary.Ignored -join ',')
    Assert-WtEqual (@($expected.Keys) -join ',') (@($summary.Results | ForEach-Object { $_.PacketRef }) -join ',')
    foreach ($result in $summary.Results) { Assert-WtEqual $expected[$result.PacketRef] $result.Code $result.PacketRef }
}
Invoke-WtTest 'ingest: accepted packets move byte-identical to packets/receipts/<packet_id>; rejects to quarantine with a note' {
    $health = $summary.Results | Where-Object { $_.PacketRef -ceq 'a02-health' }
    Assert-WtEqual ('packets/receipts/' + $health.PacketId) $health.RoutedTo
    Assert-WtEqual $inboxDigest (Get-WtTreeDigest (Join-Path $rootA $health.RoutedTo))
    foreach ($name in @('b01-seq-regression', 'b02-future', 'b03-unverified', 'b04-duplicate', 'b05-not-a-packet')) {
        $note = Read-WtJsonFile -Path (Join-Path $rootA ('packets/quarantine/' + $name + '.rejection.json')) -Object -Canonical
        Assert-WtEqual $expected[$name] $note['code']
    }
    Assert-WtEqual '_in-progress' (@([System.IO.Directory]::GetFileSystemEntries((Join-Path $rootA 'packets/inbox')) | ForEach-Object { [System.IO.Path]::GetFileName($_) }) -join ',')
}
Invoke-WtTest 'receipts: one hash-chained watchtower.telemetry.receipt.v1 row per packet with the fields LSS consumes' {
    $rows = Get-ReceiptRows $rootA
    Assert-WtEqual 9 $rows.Count
    foreach ($row in $rows) {
        foreach ($field in @('schema', 'verify_result', 'device_id', 'event_type', 'producer_time', 'seq', 'health_status', 'compliance', 'policy_hash_claimed', 'packet_id', 'event_hash', 'receipt_hash', 'prev_receipt_hash', 'receipt_id', 'fail_reason', 'signer_verified')) {
            Assert-WtTrue $row.Contains($field) ('missing ' + $field)
        }
        Assert-WtEqual 'watchtower.telemetry.receipt.v1' $row['schema']
        Assert-WtEqual $RUN1 $row['receipt_time']
    }
    Assert-WtEqual 'ok,ok,ok,ok,reject,reject,reject,reject,reject' (@($rows | ForEach-Object { $_['verify_result'] }) -join ',')
    Assert-WtEqual 'ok' $rows[1]['health_status']
    Assert-WtEqual 'compliant' $rows[2]['compliance']
    Assert-WtEqual 'match' $rows[2]['policy_check']
    Assert-WtTrue (-not $rows[6]['signer_verified'])
}
Invoke-WtTest 'receipts: rejection details never leak machine paths' {
    $text = Read-WtText (Join-Path $rootA 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson')
    Assert-WtTrue (-not $text.Contains($work)) 'absolute work path found in receipts'
    Assert-WtTrue (-not $text.Contains([System.IO.Path]::GetTempPath().TrimEnd([char[]]@('\', '/')))) 'temp path found in receipts'
}
Invoke-WtTest 'evidence: signed latest-per-device documents (heartbeat, health_report, policy_attest)' {
    foreach ($kind in @('heartbeat', 'health_report', 'policy_attest')) {
        $path = Join-Path $rootA ('runtime/devices/9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10/' + $kind + '.json')
        $doc = Read-WtJsonFile -Path $path -Object -Canonical
        Assert-WtEqual ('watchtower.' + $kind + '.v1') $doc['schema']
        Assert-WtEqual 'verified' $doc['proof_status']
        Assert-WtTrue (Test-EvidenceSignature $rootA $path) ($kind + ' signature')
    }
    $policy = Read-WtJsonFile -Path (Join-Path $rootA 'runtime/devices/9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10/policy_attest.json') -Object
    Assert-WtTrue $policy['policy_ok']
    Assert-WtEqual 'match' $policy['policy_check']
}
Invoke-WtTest 'constellation: health facet file has the shape oversight.mjs reads, freshness = observation time' {
    $files = @([System.IO.Directory]::GetFiles((Join-Path $rootA 'runtime/services/live-state-surgeon'), 'health_report*.json'))
    Assert-WtEqual 1 $files.Count
    $doc = Read-WtJsonFile -Path $files[0] -Object -Canonical
    Assert-WtEqual 'watchtower.health_report.v1' $doc['schema']
    Assert-WtEqual '2026-10-13T12:01:00Z' $doc['observed_utc']
    Assert-WtTrue (-not $doc.Contains('generated_utc')) 'generated_utc would make stale health look fresh'
    Assert-WtTrue (-not ($doc.Contains('repo') -or $doc.Contains('target_repo'))) 'machine path keys'
    Assert-WtTrue $doc['health_ok']
    Assert-WtEqual $false $doc['degraded']
    Assert-WtEqual ([long]0) $doc['failure_count']
    Assert-WtEqual 'verified' $doc['proof_status']
    Assert-WtTrue (Test-EvidenceSignature $rootA $files[0])
}
Invoke-WtTest 'alerts: verified rejections, producer alerts and unattributable forgeries' {
    $rows = Get-AlertRows $rootA
    $summaryText = @($rows | ForEach-Object { '{0}/{1}/{2}' -f $_['alert_type'], $_['severity'], $_['device_id'] }) -join ';'
    Assert-WtEqual ('PRODUCER_DRIFT/warning/9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10;TELEMETRY_REJECTED/critical/9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10;' +
        'TELEMETRY_REJECTED/critical/9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10;UNVERIFIED_PACKET/warning/unknown;TELEMETRY_REJECTED/critical/9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10;UNVERIFIED_PACKET/warning/unknown') $summaryText
    foreach ($row in $rows) { Assert-WtTrue (@($row['evidence'] | Where-Object { $_['kind'] -ceq 'watchtower_receipt_hash' }).Count -eq 1) 'alert without receipt evidence' }
    # An unverified packet's header time is attacker-writable: its alert is dated at verification.
    foreach ($row in @($rows | Where-Object { $_['alert_type'] -ceq 'UNVERIFIED_PACKET' })) { Assert-WtEqual $RUN1 $row['observed_utc'] }
}
Invoke-WtTest 'alerts: producer alert strings are bounded before they enter the ledger' {
    $root = New-StateRoot 'long-alert'
    $body = New-ReferenceBody -EventType 'watchtower.alert.v1'
    $body['alert_type'] = 'X' * 5000
    $body['reason_codes'] = @(1..100 | ForEach-Object { 'R' * 300 })
    [void](Add-InboxPacket $root 'p1' @{ EventType = 'watchtower.alert.v1'; Body = $body })
    [void](Invoke-WtIngest -Root $root -VerificationTime $RUN1)
    $row = @(Get-AlertRows $root)[0]
    Assert-WtTrue ($row['alert_type'].Length -le 160) ('alert_type length ' + $row['alert_type'].Length)
    Assert-WtEqual 32 @($row['reason_codes']).Count
    foreach ($code in $row['reason_codes']) { Assert-WtTrue ($code.Length -le 160) 'reason code not bounded' }
}
Invoke-WtTest 'seal: one signed checkpoint, one CPR-valid NFL outbox packet, one signed pledge; ledgers re-verify' {
    Assert-WtTrue (Test-WtHex64 $summary.CheckpointHash)
    $packet = Join-Path $rootA ('packets/outbox/' + $summary.OutboxPacketId)
    Assert-WtTrue (Test-WtPacket $packet).Valid
    $manifest = Read-WtJsonFile -Path (Join-Path $packet 'manifest.json') -Object -Canonical
    Assert-WtTrue (-not $manifest.Contains('packet_id'))
    Assert-WtTrue (Test-EvidenceSignature $rootA (Join-Path $packet 'manifest.json') 'packet/envelope' (Join-Path $packet 'signatures/manifest.sig')) 'signatures/manifest.sig'
    Assert-WtTrue (-not (Test-EvidenceSignature $rootA (Join-Path $packet 'manifest.json') 'watchtower' (Join-Path $packet 'signatures/manifest.sig'))) 'manifest.sig must not verify under another namespace'
    $receipt = Read-WtJsonFile -Path (Join-Path $packet 'payload/receipt.json') -Object -Canonical
    $withoutId = Copy-WtJsonValue $receipt; [void]$withoutId.Remove('receipt_id')
    Assert-WtEqual (Get-WtCanonicalHash $withoutId) $receipt['receipt_id']
    Assert-WtEqual (Read-WtText (Join-Path $rootA 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson')) (Read-WtText (Join-Path $packet 'payload/transcript_slice.ndjson'))
    $ledger = Test-WtLedger -Root $rootA
    Assert-WtTrue $ledger.Valid ('{0} {1}' -f $ledger.Code, $ledger.Detail)
    Assert-WtEqual 1 $ledger.Ledgers.Checkpoints.Count
    Assert-WtEqual 1 $ledger.Ledgers.Pledges.Count
    Assert-WtEqual 0 $ledger.Warnings.Count
    Assert-WtEqual 0 @([System.IO.Directory]::GetDirectories((Join-Path $rootA 'packets'), '_staging*') | ForEach-Object { [System.IO.Directory]::GetFileSystemEntries($_) }).Count
}
Invoke-WtTest 'records: last ingest and evidence index are canonical and consistent' {
    $record = Read-WtJsonFile -Path (Join-Path $rootA 'runtime/last_ingest.json') -Object -Canonical
    Assert-WtEqual $summary.ReceiptHead $record['receipts_head_hash']
    $index = Read-WtJsonFile -Path (Join-Path $rootA 'runtime/evidence_index.json') -Object -Canonical
    Assert-WtEqual 'verified' $index['ledgers']['telemetry_receipts']['state']
    Assert-WtEqual ([long]9) $index['ledgers']['telemetry_receipts']['count']
    Assert-WtEqual '9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10' $index['devices'][0]['device_id']
    Assert-WtEqual 'live-state-surgeon' $index['services'][0]['service_id']
}
Invoke-WtTest 'determinism: an independent node with the same state, inbox and time produces byte-identical outputs' {
    [void](Invoke-WtIngest -Root $rootB -VerificationTime $RUN1)
    foreach ($part in @('proofs', 'packets', 'runtime')) { Assert-WtEqual (Get-WtTreeDigest (Join-Path $rootA $part)) (Get-WtTreeDigest (Join-Path $rootB $part)) $part }
}

# --- run 2: chains continue, state survives restarts ------------------------------------------
Invoke-WtTest 'run 2: replays across runs are rejected, stale health never replaces newer, chains extend' {
    $accepted = Join-Path $rootA ('packets/receipts/' + ($summary.Results | Where-Object { $_.PacketRef -ceq 'a01-heartbeat' }).PacketId)
    Copy-WtTree -Source $accepted -Destination (Join-Path $rootA 'packets/inbox/c01-replay')
    [void](Add-InboxPacket $rootA 'c02-old-health' @{ EventType = 'watchtower.health_report.v1'; Seq = 5; EventId = 'evt-old'; ProducerTime = '2026-10-13T11:59:00Z'; DeviceId = 'second-device' })
    [void](Add-InboxPacket $rootA 'c03-health-fail' @{ EventType = 'watchtower.health_report.v1'; Seq = 12; ProducerTime = '2026-10-13T13:00:00Z'; Body = (New-ReferenceBody -EventType 'watchtower.health_report.v1' -HealthStatus 'fail') })
    $second = Invoke-WtIngest -Root $rootA -VerificationTime $RUN2
    Assert-WtEqual 'DUPLICATE_PACKET,OK,OK' (@($second.Results | ForEach-Object { $_.Code }) -join ',')
    $files = @([System.IO.Directory]::GetFiles((Join-Path $rootA 'runtime/services/live-state-surgeon'), 'health_report*.json') | Sort-Object)
    Assert-WtEqual 2 $files.Count
    $latest = Read-WtJsonFile -Path $files[-1] -Object
    Assert-WtEqual '2026-10-13T13:00:00Z' $latest['observed_utc']
    Assert-WtEqual $false $latest['health_ok']
    Assert-WtEqual ([long]1) $latest['failure_count']
    $ledger = Test-WtLedger -Root $rootA
    Assert-WtTrue $ledger.Valid ('{0} {1}' -f $ledger.Code, $ledger.Detail)
    Assert-WtEqual 12 $ledger.Ledgers.Receipts.Count
    Assert-WtEqual 2 $ledger.Ledgers.Checkpoints.Count
    Assert-WtEqual 2 $ledger.Ledgers.Pledges.Count
    Assert-WtTrue (@((Get-AlertRows $rootA) | Where-Object { $_['alert_type'] -ceq 'HEALTH_FAIL' -and $_['severity'] -ceq 'critical' }).Count -eq 1)
}
Invoke-WtTest 'run 3: an empty inbox appends nothing and seals nothing' {
    $before = Get-WtTreeDigest (Join-Path $rootA 'proofs')
    $third = Invoke-WtIngest -Root $rootA -VerificationTime '2026-10-13T14:00:00Z'
    Assert-WtEqual 0 $third.Processed
    Assert-WtEqual '' $third.CheckpointHash
    Assert-WtEqual $before (Get-WtTreeDigest (Join-Path $rootA 'proofs'))
}
Invoke-WtTest 'policy drift: a pinned hash mismatch is evidence, not acceptance of the claim' {
    $root = New-StateRoot 'drift' -PinnedPolicyHash ('cd' * 32)
    [void](Add-InboxPacket $root 'p1' @{ EventType = 'watchtower.policy_attest.v1' })
    [void](Invoke-WtIngest -Root $root -VerificationTime $RUN1)
    $doc = Read-WtJsonFile -Path (Join-Path $root 'runtime/devices/9b2f1f0e-6d1c-4a55-8d2e-3f0a9c1b7e10/policy_attest.json') -Object
    Assert-WtEqual $false $doc['policy_ok']
    Assert-WtEqual 'POLICY_HASH_MISMATCH' $doc['drift_reason']
    Assert-WtEqual 'POLICY_DRIFT/critical' (@((Get-AlertRows $root) | ForEach-Object { '{0}/{1}' -f $_['alert_type'], $_['severity'] }) -join ';')
}
Invoke-WtTest 'paths: unsafe device ids are stored under a hashed folder, id preserved in the document' {
    $root = New-StateRoot 'unsafe-ids'
    [void](Add-InboxPacket $root 'p1' @{ DeviceId = 'Device:NUL.' })
    [void](Invoke-WtIngest -Root $root -VerificationTime $RUN1)
    $folders = @([System.IO.Directory]::GetDirectories((Join-Path $root 'runtime/devices')) | ForEach-Object { [System.IO.Path]::GetFileName($_) })
    Assert-WtEqual 1 $folders.Count
    Assert-WtTrue ($folders[0] -cmatch '^id-[0-9a-f]{40}$') $folders[0]
    $index = Read-WtJsonFile -Path (Join-Path $root 'runtime/evidence_index.json') -Object
    Assert-WtEqual 'Device:NUL.' $index['devices'][0]['device_id']
}

# --- crash recovery: sealing resumes from the ledgers ----------------------------------------
Invoke-WtTest 'recovery: receipts appended but never sealed are sealed by the next run' {
    $root = New-StateRoot 'crash-before-seal'
    [void](Add-InboxPacket $root 'p1' @{ Seq = 1 })
    [void](Invoke-WtIngest -Root $root -VerificationTime $RUN1)
    # Simulate a crash after the receipt append: no checkpoint, outbox packet or pledge.
    foreach ($path in @('proofs/receipts/watchtower.checkpoint.v1.ndjson', 'proofs/receipts/checkpoints', 'proofs/pledges', 'packets/outbox')) {
        Remove-Item -LiteralPath (Join-Path $root $path) -Recurse -Force
    }
    $resumed = Invoke-WtIngest -Root $root -VerificationTime $RUN2
    Assert-WtEqual 0 $resumed.Processed
    Assert-WtTrue (Test-WtHex64 $resumed.CheckpointHash) 'no checkpoint was created'
    Assert-WtTrue (Test-WtHex64 $resumed.OutboxPacketId) 'no outbox packet was created'
    $ledger = Test-WtLedger -Root $root
    Assert-WtTrue $ledger.Valid ('{0} {1}' -f $ledger.Code, $ledger.Detail)
    Assert-WtEqual 1 $ledger.Ledgers.Checkpoints.Count
    Assert-WtEqual 1 $ledger.Ledgers.Pledges.Count
}
Invoke-WtTest 'recovery: a checkpoint without its outbox packet and pledge gets them, without a second checkpoint' {
    $root = New-StateRoot 'crash-after-checkpoint'
    [void](Add-InboxPacket $root 'p1' @{ Seq = 1 })
    $first = Invoke-WtIngest -Root $root -VerificationTime $RUN1
    Remove-Item -LiteralPath (Join-Path $root 'proofs/pledges') -Recurse -Force
    Remove-Item -LiteralPath (Join-Path $root 'packets/outbox') -Recurse -Force
    $resumed = Invoke-WtIngest -Root $root -VerificationTime $RUN2
    Assert-WtEqual '' $resumed.CheckpointHash 'a second checkpoint was created'
    Assert-WtEqual $first.OutboxPacketId $resumed.OutboxPacketId 'the outbox packet is not reproducible'
    $ledger = Test-WtLedger -Root $root
    Assert-WtTrue $ledger.Valid ('{0} {1}' -f $ledger.Code, $ledger.Detail)
    Assert-WtEqual 1 $ledger.Ledgers.Checkpoints.Count
    Assert-WtEqual 1 $ledger.Ledgers.Pledges.Count
}

# --- fail closed ----------------------------------------------------------------------------
Invoke-WtTest 'tamper: an edited receipt is detected and blocks further ingest without touching the inbox' {
    $root = New-StateRoot 'tamper'
    [void](Add-InboxPacket $root 'p1' @{ Seq = 1 })
    [void](Invoke-WtIngest -Root $root -VerificationTime $RUN1)
    $ledgerPath = Join-Path $root 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson'
    Write-WtText -Path $ledgerPath -Text ((Read-WtText $ledgerPath).Replace('"verify_result":"ok"', '"verify_result":"OK"'))
    Assert-WtEqual 'CHAIN_HASH_MISMATCH' (Test-WtLedger -Root $root).Code
    [void](Add-InboxPacket $root 'p2' @{ Seq = 2; EventId = 'evt-2' })
    $before = Get-WtTreeDigest (Join-Path $root 'packets/inbox')
    Assert-WtThrowsCode 'CHAIN_HASH_MISMATCH' { Invoke-WtIngest -Root $root -VerificationTime $RUN2 }
    Assert-WtEqual $before (Get-WtTreeDigest (Join-Path $root 'packets/inbox'))
    Assert-WtTrue (-not [System.IO.File]::Exists((Join-Path $root 'runtime/ingest.lock'))) 'lock left behind'
}
Invoke-WtTest 'tamper: forged checkpoint and pledge signatures are detected' {
    $root = New-StateRoot 'forged'
    [void](Add-InboxPacket $root 'p1' @{ Seq = 1 })
    $run = Invoke-WtIngest -Root $root -VerificationTime $RUN1
    $sig = Join-Path $root ('proofs/receipts/checkpoints/' + $run.CheckpointHash + '.sig')
    $saved = Read-WtBytes $sig
    Copy-Item -LiteralPath (Join-Path $root ('proofs/pledges/signatures/' + $run.PledgeHash + '.sig')) -Destination $sig -Force
    Assert-WtEqual 'LEDGER_CHECKPOINT_SIGNATURE' (Test-WtLedger -Root $root).Code
    Write-WtBytes -Path $sig -Bytes $saved
    Assert-WtTrue (Test-WtLedger -Root $root).Valid
}
Invoke-WtTest 'guards: a stale ingest lock, a missing authority key and invalid settings fail closed' {
    $root = New-StateRoot 'guards'
    New-WtDirectory (Join-Path $root 'runtime')
    Write-WtText -Path (Join-Path $root 'runtime/ingest.lock') -Text 'held'
    Assert-WtThrowsCode 'INGEST_LOCKED' { Invoke-WtIngest -Root $root -VerificationTime $RUN1 }
    [System.IO.File]::Delete((Join-Path $root 'runtime/ingest.lock'))
    $settingsPath = Join-Path $root 'config/watchtower.settings.json'
    foreach ($bad in @('svc.', 'nul', 'a/b')) {
        $settings = Read-WtJsonFile -Path $settingsPath -Object
        $settings['service_bindings'][0]['service_id'] = $bad
        Write-WtJsonFile -Path (Join-Path $root 'config/bad.json') -Value $settings
        Move-Item -LiteralPath $settingsPath -Destination (Join-Path $root 'config/good.json') -Force
        Move-Item -LiteralPath (Join-Path $root 'config/bad.json') -Destination $settingsPath -Force
        try { Assert-WtThrowsCode 'SETTINGS_VALUE' { Invoke-WtIngest -Root $root -VerificationTime $RUN1 } }
        finally { Move-Item -LiteralPath (Join-Path $root 'config/good.json') -Destination $settingsPath -Force }
    }
    $settings = Read-WtJsonFile -Path $settingsPath -Object
    $settings['service_binding'] = @()
    $saved = Read-WtText $settingsPath
    Write-WtJsonFile -Path $settingsPath -Value $settings
    try { Assert-WtThrowsCode 'SETTINGS_UNKNOWN_KEY' { Invoke-WtIngest -Root $root -VerificationTime $RUN1 } }
    finally { Write-WtText -Path $settingsPath -Text $saved }
    Move-Item -LiteralPath (Join-Path $root 'proofs/keys/watchtower_authority_ed25519') -Destination (Join-Path $root 'moved-key') -Force
    Assert-WtThrowsCode 'AUTHORITY_KEY_MISSING' { Invoke-WtIngest -Root $root -VerificationTime $RUN1 }
}
Invoke-WtTest 'doctor: healthy node publishes a signed self-check for the watchtower service' {
    $doctor = Invoke-WtDoctor -Root $rootA -VerificationTime '2026-10-13T14:30:00Z' -Publish
    Assert-WtTrue $doctor.HealthOk (@($doctor.Checks | Where-Object { -not $_['ok'] } | ForEach-Object { $_['name'] + ':' + $_['code'] }) -join ',')
    $files = @([System.IO.Directory]::GetFiles((Join-Path $rootA 'runtime/services/watchtower'), 'health_report*.json'))
    Assert-WtEqual 1 $files.Count
    $doc = Read-WtJsonFile -Path $files[0] -Object
    Assert-WtEqual 'watchtower.health_report.v1' $doc['schema']
    Assert-WtEqual '2026-10-13T14:30:00Z' $doc['observed_utc']
    Assert-WtTrue (Test-EvidenceSignature $rootA $files[0])
}
Invoke-WtTest 'doctor: a broken ledger makes the node unhealthy, never green' {
    $doctor = Invoke-WtDoctor -Root (Join-Path $work 'tamper') -VerificationTime $RUN2
    Assert-WtTrue (-not $doctor.HealthOk)
    Assert-WtEqual 'CHAIN_HASH_MISMATCH' (@($doctor.Checks | Where-Object { $_['name'] -ceq 'ledgers' })[0]['code'])
}

Remove-WtTree $work
Complete-WtTestSuite 'WATCHTOWER_INGEST_TESTS'
