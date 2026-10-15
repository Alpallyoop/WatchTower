# Constellation integrations, standalone (no sibling checkout needed):
#   - constellation.integration.receipt.v1 ledgers and their NFL witness packets
#   - the optional policy gate (watchtower > arbiter), driven by a test double of Arbiter's
#     evaluator (tests/fixtures/arbiter-stub); the real engine runs in Interop.Tests.ps1
#   - NeverLost v1 trust-bundle rules and enrolment from a NeverLost-issued bundle
. (Join-Path $PSScriptRoot 'support/TestHarness.ps1')
. (Join-Path $PSScriptRoot 'support/ReferenceProducer.ps1')
. (Join-Path $PSScriptRoot 'support/SchemaValidator.ps1')
$repo = Get-WtRepoRoot
$module = Import-Module (Join-Path $repo 'src/WatchTower/WatchTower.psd1') -Force -PassThru
$work = New-WtTempDirectory 'wt_integration_tests'
$stub = Join-Path $repo 'tests/fixtures/arbiter-stub'
$principal = 'single-tenant/device_agent/device/ref'
$keyId = 'ref-ed25519'
$producerKey = New-ReferenceProducerKey -Directory (Join-Path $work 'keys') -Name 'producer'
$schemas = Join-Path $repo 'schemas'

function Invoke-Private { param([scriptblock]$Script, [object[]]$Arguments = @()) return & $module $Script @Arguments }
function Assert-Schema {
    param([string]$Name, $Value)
    $errors = [string[]](Get-SchemaErrors -SchemaPath (Join-Path $schemas ($Name + '.json')) -Value $Value)
    Assert-WtEqual 0 $errors.Length ($Name + ': ' + ($errors -join '; '))
}
function New-Node {
    param([string]$Name, [switch]$Gate, [string]$Timeout = '')
    $node = Join-Path $work $Name
    New-WtDirectory $node
    [void](Initialize-WtTrust -Root $node -CreatedUtc '2026-10-13T00:00:00Z')
    [void](Register-WtProducer -Root $node -Principal $principal -KeyId $keyId -PublicKey ($producerKey + '.pub'))
    if ($Gate) {
        New-WtDirectory (Join-Path $node 'config/arbiter/rules')
        Copy-Item -LiteralPath (Join-Path $repo 'config/arbiter/watchtower_ingest.policyset.json') -Destination (Join-Path $node 'config/arbiter/')
        Copy-Item -LiteralPath (Join-Path $repo 'config/arbiter/rules/telemetry.rules.json') -Destination (Join-Path $node 'config/arbiter/rules/')
        $arbiter = '"policyset":"config/arbiter/watchtower_ingest.policyset.json","policy_root":"config/arbiter"'
        if ($Timeout) { $arbiter += ',"timeout_seconds":' + $Timeout }
        Write-WtText -Path (Join-Path $node 'config/watchtower.settings.json') -Text ('{"schema":"watchtower.settings.v1","arbiter":{' + $arbiter + '}}')
    }
    return $node
}
function Add-Packet {
    param([string]$Node, [string]$Name, [string]$Device = 'dev-1', [long]$Seq = 1, [string]$Time = '2026-10-13T12:00:00Z', [string]$Type = 'watchtower.heartbeat.v1')
    [void](New-ReferenceTelemetryPacket -Directory (Join-Path $Node ('packets/inbox/' + $Name)) -KeyPath $producerKey -EventType $Type -Principal $principal -KeyId $keyId -DeviceId $Device -Seq $Seq -ProducerTime $Time -EventId ('evt-' + $Name))
}
function Get-Lines { param([string]$Path) return , [string[]]((Read-WtText $Path).TrimEnd("`n").Split("`n")) }
function Get-Rows {
    param([string]$Path)
    $rows = New-Object System.Collections.ArrayList
    foreach ($line in (Get-Lines $Path)) { [void]$rows.Add((ConvertFrom-WtJson $line)) }
    return , $rows.ToArray()
}
$env:WATCHTOWER_ARBITER_ROOT = $stub

# --- integration receipt ledgers ---------------------------------------------------------------
$ledgerDir = Join-Path $work 'ledgers'
New-WtDirectory $ledgerDir
$layoutStub = [pscustomobject]@{ Root = $ledgerDir; Integrations = (Join-Path $ledgerDir 'proofs/integrations') }
Invoke-WtTest 'integration receipt: schema key order, compact, 64-zero genesis, sha256 of the line chains the next' {
    $first = Invoke-Private { param($l) Add-WtIntegrationReceipt -Layout $l -Receipt (New-WtIntegrationReceipt -Provider 'arbiter' -Contract 'policy.decision.v1' -RequestSha256 ('a' * 64) -ResponseSha256 ('b' * 64) -Outcome 'ok' -ErrorToken '' -Carried @([pscustomobject]@{ Contract = 'policy.decision.v1'; Sha256 = ('c' * 64) })) } @($layoutStub)
    $second = Invoke-Private { param($l) Add-WtIntegrationReceipt -Layout $l -Receipt (New-WtIntegrationReceipt -Provider 'arbiter' -Contract 'policy.decision.v1' -RequestSha256 '' -ResponseSha256 '' -Outcome 'unavailable' -ErrorToken 'ARBITER_NOT_FOUND') } @($layoutStub)
    $lines = Get-Lines (Join-Path $ledgerDir 'proofs/integrations/watchtower__arbiter.ndjson')
    Assert-WtEqual ('{"schema":"constellation.integration.receipt.v1","consumer":"watchtower","provider":"arbiter","emitted_by":"consumer","contract":"policy.decision.v1","request_sha256":"' + ('a' * 64) + '","response_sha256":"' + ('b' * 64) + '","carried":[{"contract":"policy.decision.v1","sha256":"' + ('c' * 64) + '"}],"outcome":"ok","error_token":null,"prev_sha256":"' + ('0' * 64) + '"}') $lines[0]
    Assert-WtEqual (Get-WtSha256 -Text $lines[0]) $first.ReceiptSha256
    Assert-WtTrue ($lines[1].Contains('"request_sha256":null,"response_sha256":null,"carried":[],"outcome":"unavailable","error_token":"ARBITER_NOT_FOUND","prev_sha256":"' + $first.ReceiptSha256 + '"'))
    Assert-WtEqual 2 $second.Index
    Assert-WtEqual 'constellation.integration.receipt.v1:watchtower>arbiter' $second.WitnessLabel
    foreach ($row in (Get-Rows (Join-Path $ledgerDir 'proofs/integrations/watchtower__arbiter.ndjson'))) { Assert-Schema 'constellation.integration.receipt.v1' $row }
}
Invoke-WtTest 'integration receipt: error_token is null exactly when the outcome is ok' {
    Assert-WtThrowsCode 'INTEGRATION_RECEIPT_INVALID' { Invoke-Private { $r = New-WtIntegrationReceipt -Provider 'arbiter' -Contract 'policy.decision.v1' -Outcome 'ok'; $r['error_token'] = 'X'; Assert-WtIntegrationReceipt $r } }
    Assert-WtThrowsCode 'INTEGRATION_RECEIPT_INVALID' { Invoke-Private { $r = New-WtIntegrationReceipt -Provider 'arbiter' -Contract 'policy.decision.v1' -Outcome 'failed' -ErrorToken 'X'; $r['error_token'] = $null; Assert-WtIntegrationReceipt $r } }
    Assert-WtThrowsCode 'INTEGRATION_RECEIPT_INVALID' { Invoke-Private { $r = New-WtIntegrationReceipt -Provider 'Arbiter' -Contract 'policy.decision.v1' -Outcome 'ok'; Assert-WtIntegrationReceipt $r } }
    Assert-WtThrowsCode 'INTEGRATION_RECEIPT_INVALID' { Invoke-Private { $r = New-WtIntegrationReceipt -Provider 'arbiter' -Contract 'policy.decision' -Outcome 'ok'; Assert-WtIntegrationReceipt $r } }
    Assert-WtThrowsCode 'INTEGRATION_RECEIPT_INVALID' { Invoke-Private { $r = New-WtIntegrationReceipt -Provider 'arbiter' -Contract 'policy.decision.v1' -Outcome 'failed' -ErrorToken 'lower_case'; Assert-WtIntegrationReceipt $r } }
    # One-element arrays where strings belong must not slip through PowerShell's array filtering.
    Assert-WtThrowsCode 'INTEGRATION_RECEIPT_INVALID' { Invoke-Private { $r = New-WtIntegrationReceipt -Provider 'arbiter' -Contract 'policy.decision.v1' -Outcome 'ok'; $r['outcome'] = [System.Collections.ArrayList]@('ok'); Assert-WtIntegrationReceipt $r } }
    Assert-WtThrowsCode 'INTEGRATION_RECEIPT_INVALID' { Invoke-Private { $r = New-WtIntegrationReceipt -Provider 'arbiter' -Contract 'policy.decision.v1' -Outcome 'ok'; $r['emitted_by'] = [System.Collections.ArrayList]@('consumer'); Assert-WtIntegrationReceipt $r } }
}
Invoke-WtTest 'integration ledger: tampering, reordered keys, a partial line and CR all fail closed' {
    $path = Join-Path $ledgerDir 'proofs/integrations/watchtower__arbiter.ndjson'
    $good = Read-WtText $path
    $cases = @(
        @('INTEGRATION_LEDGER_CHAIN_MISMATCH', ($good.Replace('"request_sha256":"' + ('a' * 64), '"request_sha256":"' + ('d' * 64)))),
        @('INTEGRATION_LEDGER_NONCANONICAL', ($good.Replace('"consumer":"watchtower","provider":"arbiter"', '"provider":"arbiter","consumer":"watchtower"'))),
        @('INTEGRATION_LEDGER_PARTIAL', $good.TrimEnd("`n")),
        @('INTEGRATION_LEDGER_CR', $good.Replace("`n", "`r`n")),
        @('INTEGRATION_RECEIPT_INVALID', ($good.Replace('"emitted_by":"consumer"', '"emitted_by":"witness"'))))
    foreach ($case in $cases) {
        $copy = Join-Path $ledgerDir ('copy_' + $case[0] + '.ndjson')
        [System.IO.File]::WriteAllBytes($copy, (ConvertTo-WtUtf8 $case[1]))
        Assert-WtThrowsCode $case[0] { Invoke-Private { param($p) Read-WtIntegrationLedger $p } @($copy) }
    }
}
Invoke-WtTest 'integration ledger: an append never extends a damaged ledger' {
    $path = Join-Path $ledgerDir 'proofs/integrations/watchtower__neverlost.ndjson'
    [void](Invoke-Private { param($l) Add-WtIntegrationReceipt -Layout $l -Receipt (New-WtIntegrationReceipt -Provider 'neverlost' -Contract 'neverlost.trust_bundle.v1' -Outcome 'ok') } @($layoutStub))
    Add-Content -LiteralPath $path -Value 'junk' -NoNewline
    $before = Get-WtSha256 -Path $path
    Assert-WtThrowsCode 'INTEGRATION_LEDGER_PARTIAL' { Invoke-Private { param($l) Add-WtIntegrationReceipt -Layout $l -Receipt (New-WtIntegrationReceipt -Provider 'neverlost' -Contract 'neverlost.trust_bundle.v1' -Outcome 'ok') } @($layoutStub) }
    Assert-WtEqual $before (Get-WtSha256 -Path $path)
}

# --- policy gate --------------------------------------------------------------------------------
Invoke-WtTest 'policy gate off: receipts carry no policy_decision and no integration ledger is written' {
    $node = New-Node 'off'
    Add-Packet $node 'a'
    $run = Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:05:00Z'
    Assert-WtEqual 1 $run.Accepted
    $row = (Get-Rows (Join-Path $node 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson'))[0]
    Assert-WtTrue (-not $row.Contains('policy_decision'))
    Assert-WtTrue (-not (Test-Path -LiteralPath (Join-Path $node 'proofs/integrations')))
    Assert-WtEqual '' $run.IntegrationWitnessPacketId
}
$gated = New-Node 'gated' -Gate
Add-Packet $gated 'a_allow' 'dev-1' 1
Add-Packet $gated 'b_deny' 'deny-1' 1
Add-Packet $gated 'c_quar' 'quar-1' 1 '2026-10-13T12:00:00Z' 'watchtower.health_report.v1'
Add-Packet $gated 'd_crash' 'crash-1' 1
Add-Packet $gated 'e_badhash' 'badhash-1' 1
Add-Packet $gated 'f_staleat' 'staleat-1' 1
Add-Packet $gated 'g_arrays' 'arrays-1' 1
$gatedRun = Invoke-WtIngest -Root $gated -VerificationTime '2026-10-13T12:05:00Z'
$gatedRows = Get-Rows (Join-Path $gated 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson')
$gatedIntegration = Get-Rows (Join-Path $gated 'proofs/integrations/watchtower__arbiter.ndjson')
function Get-GatedRow { param([string]$Ref) return ($gatedRows | Where-Object { $_['packet_ref'] -ceq $Ref }) }

Invoke-WtTest 'policy gate: allow is accepted, linked to an ok integration receipt, and its evidence re-proves' {
    $row = Get-GatedRow 'a_allow'
    Assert-WtEqual 'ok' $row['verify_result']
    $block = $row['policy_decision']
    Assert-WtEqual 'allow' $block['decision']; Assert-WtEqual 'ok' $block['outcome']; Assert-WtEqual 'STUB_ALLOW' $block['matched_rule_id']
    $lines = Get-Lines (Join-Path $gated 'proofs/integrations/watchtower__arbiter.ndjson')
    $linked = @($lines | Where-Object { (Get-WtSha256 -Text $_) -ceq $block['integration_receipt_sha256'] })
    Assert-WtEqual 1 $linked.Count
    $receipt = ConvertFrom-WtJson $linked[0]
    Assert-WtEqual $block['input_hash'].Substring(7) $receipt['request_sha256']
    Assert-WtEqual $block['decision_hash'].Substring(7) $receipt['carried'][0]['sha256']
    foreach ($path in @(('proofs/policy/inputs/' + $block['input_hash'].Substring(7) + '.json'), ('proofs/policy/decisions/' + $block['decision_hash'].Substring(7) + '.json'), ('proofs/policy/sets/' + $block['policy_hash'].Substring(7) + '/policyset.json'))) {
        Assert-WtTrue (Test-Path -LiteralPath (Join-Path $gated $path)) ($path + ' missing')
    }
    Assert-Schema 'watchtower.telemetry.receipt.v1' $row
}
Invoke-WtTest 'policy gate: deny and quarantine are quarantined at stage policy with the decision recorded' {
    $deny = Get-GatedRow 'b_deny'
    Assert-WtEqual 'reject' $deny['verify_result']; Assert-WtEqual 'policy' $deny['stage']; Assert-WtEqual 'POLICY_DENY' $deny['fail_reason']['code']
    Assert-WtTrue $deny['signer_verified']
    $quar = Get-GatedRow 'c_quar'
    Assert-WtEqual 'POLICY_QUARANTINE' $quar['fail_reason']['code']
    Assert-WtEqual 'route_to_quarantine,notify_operator' ($quar['policy_decision']['obligations'] -join ',')
    Assert-WtEqual 'ok' $quar['health_status'] 'facts of a policy-rejected packet are still recorded'
    $note = Read-WtJsonFile -Path (Join-Path $gated 'packets/quarantine/c_quar.rejection.json') -Object -Canonical
    Assert-WtEqual 'quarantine' $note['policy_decision']
    Assert-WtEqual 'stub' $note['obligations'][0]['params']['queue']
    Assert-Schema 'watchtower.quarantine_note.v1' $note
    foreach ($row in @($deny, $quar)) { Assert-Schema 'watchtower.telemetry.receipt.v1' $row }
}
Invoke-WtTest 'policy gate: an evaluator failure is a deny (fail closed) with a failed integration receipt and a critical alert' {
    $crash = Get-GatedRow 'd_crash'
    Assert-WtEqual 'POLICY_EVALUATOR_FAILED' $crash['fail_reason']['code']
    Assert-WtEqual 'deny' $crash['policy_decision']['decision']
    Assert-WtEqual 'failed' $crash['policy_decision']['outcome']
    Assert-WtEqual 'ARBITER_E_STUB' $crash['policy_decision']['error_token']
    Assert-WtEqual '' $crash['policy_decision']['decision_hash']
    $alerts = Get-Rows (Join-Path $gated 'proofs/alerts/watchtower.alert.v1.ndjson')
    $alert = $alerts | Where-Object { @($_['evidence'] | Where-Object { $_['value'] -ceq $crash['receipt_hash'] }).Count -gt 0 }
    Assert-WtEqual 'critical' $alert['severity']
    Assert-WtEqual 'POLICY_EVALUATOR_FAILED' $alert['reason']
    $deny = Get-GatedRow 'b_deny'
    $denyAlert = $alerts | Where-Object { @($_['evidence'] | Where-Object { $_['value'] -ceq $deny['receipt_hash'] }).Count -gt 0 }
    Assert-WtEqual 'warning' $denyAlert['severity']
}
Invoke-WtTest 'policy gate: decisions are re-verified, never trusted (wrong decision_hash, evaluated_at not env.now)' {
    foreach ($ref in @('e_badhash', 'f_staleat', 'g_arrays')) {
        $row = Get-GatedRow $ref
        Assert-WtEqual 'POLICY_DECISION_INVALID' $row['fail_reason']['code'] $ref
        Assert-WtEqual 'failed' $row['policy_decision']['outcome'] $ref
    }
}
Invoke-WtTest 'policy gate: one integration receipt per exchange, all witnessed in one outbox packet' {
    Assert-WtEqual 7 $gatedIntegration.Count
    Assert-WtEqual 'ok,ok,ok,failed,failed,failed,failed' (($gatedIntegration | ForEach-Object { $_['outcome'] }) -join ',')
    Assert-WtTrue ($gatedRun.IntegrationWitnessPacketId -cmatch '^[0-9a-f]{64}$')
    $packet = Join-Path $gated ('packets/outbox/' + $gatedRun.IntegrationWitnessPacketId)
    Assert-WtTrue (Test-WtPacket $packet).Valid
    $manifest = Read-WtJsonFile -Path (Join-Path $packet 'manifest.json') -Object -Canonical
    Assert-Schema 'watchtower.integration_witness.v1' $manifest
    Assert-WtEqual 'watchtower>arbiter' $manifest['ledgers'][0]['integration']
    Assert-WtEqual 7 $manifest['ledgers'][0]['receipt_sha256'].Count
    Assert-WtEqual (Get-WtSha256 -Path (Join-Path $gated 'proofs/integrations/watchtower__arbiter.ndjson')) (Get-WtSha256 -Path (Join-Path $packet 'payload/integration_receipts/watchtower__arbiter.ndjson'))
    $ok = Invoke-Private { param($n, $p) $b = Read-WtTrustBundle (Join-Path $n 'proofs/trust/neverlost/trust_bundle.json'); Test-WtAuthoritySignature -Bundle $b -Namespace 'packet/envelope' -SignaturePath (Join-Path $p 'signatures/manifest.sig') -MessagePath (Join-Path $p 'manifest.json') } @($gated, $packet)
    Assert-WtTrue $ok 'witness manifest signature'
    foreach ($row in (Get-Rows (Join-Path $gated 'proofs/integrations/watchtower.integration_witness_record.v1.ndjson'))) { Assert-Schema 'watchtower.integration_witness_record.v1' $row }
    Assert-Schema 'watchtower.ingest_run.v1' (Read-WtJsonFile -Path (Join-Path $gated 'runtime/last_ingest.json') -Object)
    Assert-Schema 'watchtower.evidence_index.v1' (Read-WtJsonFile -Path (Join-Path $gated 'runtime/evidence_index.json') -Object)
    Assert-WtEqual $null (Publish-WtIntegrationReceipts -Root $gated -VerificationTime '2026-10-13T12:06:00Z')
    # A witness run takes the ingest writer lock, so it can never fork the witness ledger.
    $lock = Join-Path $gated 'runtime/ingest.lock'
    Write-WtText -Path $lock -Text 'held'
    try { Assert-WtThrowsCode 'INGEST_LOCKED' { Publish-WtIntegrationReceipts -Root $gated -VerificationTime '2026-10-13T12:06:00Z' } }
    finally { Remove-Item -LiteralPath $lock }
}
Invoke-WtTest 'policy gate: ledger, integrations and doctor all re-verify the gated node' {
    $ledger = Test-WtLedger -Root $gated
    Assert-WtTrue $ledger.Valid ('{0} {1}' -f $ledger.Code, $ledger.Detail)
    Assert-WtEqual 0 @($ledger.Warnings).Count (@($ledger.Warnings) -join '; ')
    $integrations = Test-WtIntegrations -Root $gated
    Assert-WtTrue $integrations.Valid $integrations.Detail
    $doctor = Invoke-WtDoctor -Root $gated -VerificationTime '2026-10-13T12:06:00Z'
    Assert-WtTrue $doctor.HealthOk (@($doctor.Checks | Where-Object { -not $_['ok'] } | ForEach-Object { $_['name'] + ' ' + $_['code'] }) -join '; ')
    Assert-WtEqual 'OK' (@($doctor.Checks | Where-Object { $_['name'] -ceq 'policy_gate' })[0]['code'])
}
Invoke-WtTest 'policy gate: a packet held back by policy can be delivered again and accepted' {
    $node = New-Node 'resubmit' -Gate
    Add-Packet $node 'a' 'quar-9' 1
    [void](Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:05:00Z')
    Copy-WtTree -Source (Join-Path $node 'packets/quarantine/a') -Destination (Join-Path $node 'packets/inbox/a_again')
    Write-WtText -Path (Join-Path $node 'config/watchtower.settings.json') -Text '{"schema":"watchtower.settings.v1"}'
    $run = Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:06:00Z'
    Assert-WtEqual 1 $run.Accepted
    Assert-WtTrue (Test-WtLedger -Root $node).Valid
}
Invoke-WtTest 'policy gate: tampered policy evidence is detected by the ledger check' {
    $node = Join-Path $work 'gated-tamper'
    Copy-WtTree -Source $gated -Destination $node
    $block = (Get-GatedRow 'a_allow')['policy_decision']
    $decision = Join-Path $node ('proofs/policy/decisions/' + $block['decision_hash'].Substring(7) + '.json')
    Write-WtText -Path $decision -Text ((Read-WtText $decision).Replace('"STUB_ALLOW"', '"STUB_ALLOW_X"'))
    Assert-WtEqual 'LEDGER_POLICY_DECISION' (Test-WtLedger -Root $node).Code
    $node2 = Join-Path $work 'gated-tamper-input'
    Copy-WtTree -Source $gated -Destination $node2
    $inputFile = Join-Path $node2 ('proofs/policy/inputs/' + $block['input_hash'].Substring(7) + '.json')
    Write-WtText -Path $inputFile -Text ((Read-WtText $inputFile).Replace('"ingest"', '"other"'))
    Assert-WtEqual 'LEDGER_POLICY_INPUT' (Test-WtLedger -Root $node2).Code
    $node3 = Join-Path $work 'gated-tamper-integration'
    Copy-WtTree -Source $gated -Destination $node3
    $ledgerPath = Join-Path $node3 'proofs/integrations/watchtower__arbiter.ndjson'
    Write-WtText -Path $ledgerPath -Text ((Read-WtText $ledgerPath).Replace('"outcome":"failed","error_token":"ARBITER_E_STUB"', '"outcome":"failed","error_token":"ARBITER_E_STUX"'))
    Assert-WtEqual 'LEDGER_INTEGRATION_INVALID' (Test-WtLedger -Root $node3).Code
    $node4 = Join-Path $work 'gated-tamper-witness'
    Copy-WtTree -Source $gated -Destination $node4
    $carried = Join-Path $node4 ('packets/outbox/' + $gatedRun.IntegrationWitnessPacketId + '/payload/integration_receipts/watchtower__arbiter.ndjson')
    Add-Content -LiteralPath $carried -Value 'x' -NoNewline
    Assert-WtEqual 'LEDGER_WITNESS_PACKET_INVALID' (Test-WtLedger -Root $node4).Code
}
Invoke-WtTest 'policy gate: engine missing, policy unreadable and timeout each fail closed with the right outcome' {
    $node = New-Node 'unavailable' -Gate
    Add-Packet $node 'a'
    $saved = $env:WATCHTOWER_ARBITER_ROOT
    $env:WATCHTOWER_ARBITER_ROOT = Join-Path $work 'no-such-arbiter'
    try { [void](Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:05:00Z') } finally { $env:WATCHTOWER_ARBITER_ROOT = $saved }
    $row = (Get-Rows (Join-Path $node 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson'))[0]
    Assert-WtEqual 'POLICY_EVALUATOR_UNAVAILABLE' $row['fail_reason']['code']
    $receipt = (Get-Rows (Join-Path $node 'proofs/integrations/watchtower__arbiter.ndjson'))[0]
    Assert-WtEqual 'unavailable' $receipt['outcome']; Assert-WtEqual $null $receipt['request_sha256']; Assert-WtEqual 'ARBITER_NOT_FOUND' $receipt['error_token']
    $doctor = Invoke-WtDoctor -Root $node -VerificationTime '2026-10-13T12:06:00Z'
    $env:WATCHTOWER_ARBITER_ROOT = $saved

    $node = New-Node 'badpolicy' -Gate
    Remove-Item -LiteralPath (Join-Path $node 'config/arbiter/rules/telemetry.rules.json')
    Add-Packet $node 'a'
    [void](Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:05:00Z')
    $row = (Get-Rows (Join-Path $node 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson'))[0]
    Assert-WtEqual 'POLICY_SET_INVALID' $row['fail_reason']['code']
    $receipt = (Get-Rows (Join-Path $node 'proofs/integrations/watchtower__arbiter.ndjson'))[0]
    Assert-WtEqual 'refused' $receipt['outcome']
    Assert-WtEqual 'POLICY_SET_INVALID' (@((Invoke-WtDoctor -Root $node -VerificationTime '2026-10-13T12:06:00Z').Checks | Where-Object { $_['name'] -ceq 'policy_gate' })[0]['code'])

    $node = New-Node 'timeout' -Gate -Timeout '2'
    Add-Packet $node 'a' 'sleep-1'
    [void](Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:05:00Z')
    $row = (Get-Rows (Join-Path $node 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson'))[0]
    Assert-WtEqual 'POLICY_EVALUATOR_TIMEOUT' $row['fail_reason']['code']
    Assert-WtEqual 'unknown' ((Get-Rows (Join-Path $node 'proofs/integrations/watchtower__arbiter.ndjson'))[0]['outcome'])
}
Invoke-WtTest 'policy gate: two nodes with the same state, inputs and time write byte-identical evidence' {
    $first = New-Node 'det-a' -Gate
    $second = Join-Path $work 'det-b'
    Copy-WtTree -Source $first -Destination $second
    foreach ($node in @($first, $second)) {
        Add-Packet $node 'a' 'dev-7' 1
        Add-Packet $node 'b' 'deny-7' 1
        [void](Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:05:00Z')
    }
    foreach ($relative in @('proofs/receipts/watchtower.telemetry.receipt.v1.ndjson', 'proofs/integrations/watchtower__arbiter.ndjson',
            'proofs/integrations/watchtower.integration_witness_record.v1.ndjson', 'runtime/last_ingest.json')) {
        Assert-WtEqual (Get-WtSha256 -Path (Join-Path $first $relative)) (Get-WtSha256 -Path (Join-Path $second $relative)) $relative
    }
    Assert-WtEqual (Get-WtTreeDigest (Join-Path $first 'proofs/policy')) (Get-WtTreeDigest (Join-Path $second 'proofs/policy'))
}
Invoke-WtTest 'settings: the arbiter block is validated (unknown keys, absolute paths, timeout range)' {
    $node = New-Node 'settings'
    $cases = @(
        @('SETTINGS_UNKNOWN_KEY', '{"schema":"watchtower.settings.v1","arbiter":{"policyset":"p.json","policy_root":"p","engine":"/x"}}'),
        @('SETTINGS_VALUE', '{"schema":"watchtower.settings.v1","arbiter":{"policyset":"/etc/p.json","policy_root":"p"}}'),
        @('SETTINGS_VALUE', '{"schema":"watchtower.settings.v1","arbiter":{"policyset":"../p.json","policy_root":"p"}}'),
        @('SETTINGS_VALUE', '{"schema":"watchtower.settings.v1","arbiter":{"policyset":"p.json","policy_root":"p","timeout_seconds":0}}'),
        @('FIELD_MISSING', '{"schema":"watchtower.settings.v1","arbiter":{"policyset":"p.json"}}'))
    foreach ($case in $cases) {
        Write-WtText -Path (Join-Path $node 'config/watchtower.settings.json') -Text $case[1]
        Assert-WtThrowsCode $case[0] { Invoke-Private { param($n) Read-WtSettings (Get-WtLayout $n) } @($node) }
    }
    $example = Read-WtJsonFile -Path (Join-Path $repo 'config/watchtower.settings.example.json') -Object
    Assert-Schema 'watchtower.settings.v1' $example
}

# --- NeverLost v1 trust bundles -----------------------------------------------------------------
Invoke-WtTest 'trust: every key carries pubkey_path and pubkey_sha256 over the exact key file (NeverLost v1)' {
    $node = New-Node 'nl'
    $bundle = Read-WtJsonFile -Path (Join-Path $node 'proofs/trust/neverlost/trust_bundle.json') -Object -Canonical
    foreach ($entry in $bundle['principals']) {
        foreach ($key in $entry['keys']) {
            Assert-WtEqual (Get-WtSha256 -Path (Join-Path $node $key['pubkey_path'])) $key['pubkey_sha256'] $key['key_id']
        }
    }
    Assert-WtEqual 'proofs/keys/watchtower_authority_ed25519.pub' $bundle['principals'][0]['keys'][0]['pubkey_path']
    Assert-WtEqual 'proofs/trust/neverlost/keys/ref-ed25519.pub' $bundle['principals'][1]['keys'][0]['pubkey_path']
}
Invoke-WtTest 'trust: a changed or missing key file fails closed everywhere the bundle is read' {
    $node = New-Node 'nl-tamper'
    $file = Join-Path $node 'proofs/trust/neverlost/keys/ref-ed25519.pub'
    Write-WtText -Path $file -Text ((Read-WtText $file).TrimEnd("`n") + ' comment')
    Assert-WtThrowsCode 'TRUST_PUBKEY_SHA256_MISMATCH' { Get-WtTrust -Root $node }
    Assert-WtEqual 'TRUST_PUBKEY_SHA256_MISMATCH' (Test-WtLedger -Root $node).Code
    Remove-Item -LiteralPath $file
    Assert-WtThrowsCode 'TRUST_PUBKEY_FILE_MISSING' { Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:05:00Z' }
}
Invoke-WtTest 'trust: key ids are unique across the whole bundle; a refused enrolment leaves no key file' {
    $node = New-Node 'nl-dup'
    $other = New-ReferenceProducerKey -Directory (Join-Path $work 'keys-dup') -Name 'other'
    $keys = Join-Path $node 'proofs/trust/neverlost/keys'
    $before = @(Get-ChildItem -LiteralPath $keys).Count
    Assert-WtThrowsCode 'TRUST_DUPLICATE_KEY_ID' { Register-WtProducer -Root $node -Principal 'single-tenant/device_agent/device/other' -KeyId 'REF-ed25519' -PublicKey ($other + '.pub') }
    Assert-WtThrowsCode 'TRUST_PRINCIPAL_FORMAT' { Register-WtProducer -Root $node -Principal 'bad principal' -KeyId 'k1' -PublicKey ($other + '.pub') }
    Assert-WtEqual $before @(Get-ChildItem -LiteralPath $keys).Count
    Assert-WtTrue (Register-WtProducer -Root $node -Principal 'single-tenant/device_agent/device/other' -KeyId 'k1' -PublicKey ($other + '.pub')).Changed
}
Invoke-WtTest 'trust: init adds pubkey_path to a bundle written before 2.1.0 and leaves allowed_signers unchanged' {
    $node = New-Node 'nl-upgrade'
    $path = Join-Path $node 'proofs/trust/neverlost/trust_bundle.json'
    $bundle = Read-WtJsonFile -Path $path -Object
    [void]$bundle['principals'][0]['keys'][0].Remove('pubkey_path')
    Invoke-Private { param($p, $b) Write-WtJsonFile -Path $p -Value $b } @($path, $bundle)
    $signers = Get-WtSha256 -Path (Join-Path $node 'proofs/trust/neverlost/allowed_signers')
    [void](Initialize-WtTrust -Root $node -CreatedUtc '2026-10-14T00:00:00Z')
    Assert-WtEqual 'proofs/keys/watchtower_authority_ed25519.pub' (Read-WtJsonFile -Path $path -Object)['principals'][0]['keys'][0]['pubkey_path']
    Assert-WtEqual $signers (Get-WtSha256 -Path (Join-Path $node 'proofs/trust/neverlost/allowed_signers'))
}

# A NeverLost-issued producer bundle, in NeverLost's own layout (<root>/proofs/trust/trust_bundle.json).
function New-NeverLostSource {
    param([string]$Name, [string]$Principal = 'single-tenant/device_agent/device/lss-07', [string[]]$Namespaces = @('watchtower/packet', 'watchtower/telemetry-heartbeat'), [switch]$NoPath)
    $root = Join-Path $work $Name
    New-WtDirectory (Join-Path $root 'proofs/keys')
    New-WtDirectory (Join-Path $root 'proofs/trust')
    $key = New-ReferenceProducerKey -Directory (Join-Path $root 'private') -Name 'lss07'
    Copy-Item -LiteralPath ($key + '.pub') -Destination (Join-Path $root 'proofs/keys/lss07_ed25519.pub')
    $entry = [ordered]@{ key_id = 'lss-07-ed25519'; alg = 'ssh-ed25519'; pubkey = (ConvertTo-WtPublicKey (Read-WtText ($key + '.pub'))); namespaces = $Namespaces }
    if (-not $NoPath) { $entry['pubkey_path'] = 'proofs/keys/lss07_ed25519.pub'; $entry['pubkey_sha256'] = Get-WtSha256 -Path (Join-Path $root 'proofs/keys/lss07_ed25519.pub') }
    $bundle = [ordered]@{ schema = 'neverlost.trust_bundle.v1'; created_utc = '2026-10-15T00:00:00Z'; principals = @([ordered]@{ principal = $Principal; keys = @($entry) }) }
    $path = Join-Path $root 'proofs/trust/trust_bundle.json'
    Invoke-Private { param($p, $b) Write-WtJsonFile -Path $p -Value (Copy-WtJsonValue $b) } @($path, $bundle)
    return [pscustomobject]@{ Root = $root; Bundle = $path; Key = $key }
}
Invoke-WtTest 'neverlost: enrolment from a NeverLost bundle writes an ok receipt carrying the authorising neverlost.receipt.v1 line' {
    $node = New-Node 'nl-import'
    $source = New-NeverLostSource 'nl-source'
    $bundleSha = Get-WtSha256 -Path $source.Bundle
    $line = '{"schema":"neverlost.operator.authority.started.v1","action":"authority.started","trust_bundle_sha256":"' + $bundleSha + '"}'
    Write-WtText -Path (Join-Path $work 'nl-receipt.ndjson') -Text $line
    $result = Import-WtNeverLostProducer -Root $node -BundlePath $source.Bundle -Principal 'single-tenant/device_agent/device/lss-07' -NeverLostReceipt (Join-Path $work 'nl-receipt.ndjson')
    Assert-WtEqual 1 @($result.Enrolled).Count
    $trust = Get-WtTrust -Root $node
    Assert-WtTrue $trust.AllowedSignersDerived
    $entry = @($trust.Principals | Where-Object { $_.KeyId -ceq 'lss-07-ed25519' })[0]
    Assert-WtEqual 'watchtower/packet,watchtower/telemetry-heartbeat' (@($entry.Namespaces) -join ',')
    $receipt = (Get-Rows (Join-Path $node 'proofs/integrations/watchtower__neverlost.ndjson'))[0]
    Assert-WtEqual 'ok' $receipt['outcome']; Assert-WtEqual 'neverlost.trust_bundle.v1' $receipt['contract']; Assert-WtEqual $bundleSha $receipt['response_sha256']
    Assert-WtEqual (Get-WtSha256 -Text $line) $receipt['carried'][0]['sha256']
    Assert-WtEqual 'neverlost.receipt.v1' $receipt['carried'][0]['contract']
    Add-Packet $node 'x'
    # The imported producer signs with its own key: reuse the generic producer for a smoke ingest.
    $run = Invoke-WtIngest -Root $node -VerificationTime '2026-10-15T12:05:00Z'
    Assert-WtEqual 1 $run.Accepted
    Assert-WtTrue ($run.IntegrationWitnessPacketId -cmatch '^[0-9a-f]{64}$') 'the enrolment receipt is witnessed by the next ingest'
}
Invoke-WtTest 'neverlost: principal-level namespaces count; a refusal part-way through enrols nothing' {
    $node = New-Node 'nl-shared'
    $source = New-NeverLostSource 'nl-shared-src' -Namespaces @('watchtower/packet')
    $bundle = Read-WtJsonFile -Path $source.Bundle -Object
    $bundle['principals'][0]['namespaces'] = @('watchtower/telemetry-health')
    $second = New-ReferenceProducerKey -Directory (Join-Path $source.Root 'private') -Name 'second' -Comment 'TEST_ONLY second'
    Copy-Item -LiteralPath ($second + '.pub') -Destination (Join-Path $source.Root 'proofs/keys/second.pub')
    $entry = [ordered]@{ key_id = 'lss-07-second'; alg = 'ssh-ed25519'; pubkey = (ConvertTo-WtPublicKey (Read-WtText ($second + '.pub'))); pubkey_path = 'proofs/keys/second.pub'; pubkey_sha256 = (Get-WtSha256 -Path (Join-Path $source.Root 'proofs/keys/second.pub')); namespaces = @('watchtower/packet') }
    [void]$bundle['principals'][0]['keys'].Add((Copy-WtJsonValue $entry))
    Invoke-Private { param($p, $b) Write-WtJsonFile -Path $p -Value $b } @($source.Bundle, $bundle)
    $before = Get-WtSha256 -Path (Join-Path $node 'proofs/trust/neverlost/trust_bundle.json')
    # The second key is marked TEST_ONLY: refused, so the first must be rolled back too.
    Assert-WtThrowsCode 'TRUST_TEST_KEY_REFUSED' { Import-WtNeverLostProducer -Root $node -BundlePath $source.Bundle -Principal 'single-tenant/device_agent/device/lss-07' }
    Assert-WtEqual $before (Get-WtSha256 -Path (Join-Path $node 'proofs/trust/neverlost/trust_bundle.json'))
    Assert-WtTrue (-not (Test-Path -LiteralPath (Join-Path $node 'proofs/trust/neverlost/keys/lss-07-ed25519.pub'))) 'rolled back key file'
    $result = Import-WtNeverLostProducer -Root $node -BundlePath $source.Bundle -Principal 'single-tenant/device_agent/device/lss-07' -KeyId 'lss-07-ed25519'
    $entry = @((Get-WtTrust -Root $node).Principals | Where-Object { $_.KeyId -ceq 'lss-07-ed25519' })[0]
    Assert-WtEqual 'watchtower/packet,watchtower/telemetry-health' (@($entry.Namespaces) -join ',')
    $rows = Get-Rows (Join-Path $node 'proofs/integrations/watchtower__neverlost.ndjson')
    Assert-WtEqual 'failed,ok' (($rows | ForEach-Object { $_['outcome'] }) -join ',')
}
Invoke-WtTest 'neverlost: every refusal is recorded as a failed or unavailable exchange' {
    $node = New-Node 'nl-refuse'
    $good = New-NeverLostSource 'nl-good'
    $cases = @(
        @('TRUST_SOURCE_MISSING', 'unavailable', { Import-WtNeverLostProducer -Root $node -BundlePath (Join-Path $work 'none.json') -Principal 'single-tenant/device_agent/device/lss-07' }),
        @('TRUST_SOURCE_ROLE', 'failed', { $s = New-NeverLostSource 'nl-role' -Principal 'single-tenant/operator/alec'; Import-WtNeverLostProducer -Root $node -BundlePath $s.Bundle -Principal 'single-tenant/operator/alec' }),
        @('TRUST_SOURCE_NOT_NEVERLOST_V1', 'failed', { $s = New-NeverLostSource 'nl-nopath' -NoPath; Import-WtNeverLostProducer -Root $node -BundlePath $s.Bundle -Principal 'single-tenant/device_agent/device/lss-07' }),
        @('TRUST_NAMESPACE_NOT_PRODUCER', 'failed', { $s = New-NeverLostSource 'nl-ns' -Namespaces @('watchtower'); Import-WtNeverLostProducer -Root $node -BundlePath $s.Bundle -Principal 'single-tenant/device_agent/device/lss-07' }),
        @('TRUST_RECEIPT_MISMATCH', 'failed', { Write-WtText -Path (Join-Path $work 'bad-receipt') -Text ('{"schema":"neverlost.receipt.v1","trust_bundle_sha256":"' + ('0' * 64) + '"}'); Import-WtNeverLostProducer -Root $node -BundlePath $good.Bundle -Principal 'single-tenant/device_agent/device/lss-07' -NeverLostReceipt (Join-Path $work 'bad-receipt') }),
        @('TRUST_NAMESPACE_NOT_GRANTED', 'failed', { Import-WtNeverLostProducer -Root $node -BundlePath $good.Bundle -Principal 'single-tenant/device_agent/device/lss-07' -Namespace @('watchtower/telemetry-health') }),
        @('TRUST_PUBKEY_SHA256_MISMATCH', 'failed', { $s = New-NeverLostSource 'nl-keyfile'; Add-Content -LiteralPath (Join-Path $s.Root 'proofs/keys/lss07_ed25519.pub') -Value ' ' -NoNewline; Import-WtNeverLostProducer -Root $node -BundlePath $s.Bundle -Principal 'single-tenant/device_agent/device/lss-07' }))
    $n = 0
    foreach ($case in $cases) {
        $n++
        Assert-WtThrowsCode $case[0] $case[2]
        $rows = Get-Rows (Join-Path $node 'proofs/integrations/watchtower__neverlost.ndjson')
        Assert-WtEqual $n $rows.Count $case[0]
        Assert-WtEqual $case[1] $rows[$n - 1]['outcome'] $case[0]
        Assert-WtEqual $case[0] $rows[$n - 1]['error_token'] $case[0]
    }
    Assert-WtEqual 2 @((Get-WtTrust -Root $node).Principals).Count 'nothing was enrolled'
}

# --- live-state-surgeon: packets its own emitter produced (fixtures, see PROVENANCE.md) -----------
Invoke-WtTest 'lss: packets from live-state-surgeon''s fixed emitter are accepted end to end (DoD I1)' {
    $node = Join-Path $work 'lss'
    New-WtDirectory $node
    [void](Initialize-WtTrust -Root $node -CreatedUtc '2026-03-12T00:00:00Z')
    $fixtures = Join-Path $repo 'tests/fixtures/interop/live-state-surgeon'
    [void](Register-WtProducer -Root $node -Principal 'lss-dev' -KeyId 'lss-dev-ed25519' -PublicKey (Join-Path $fixtures 'lss-dev.pub'))
    Write-WtText -Path (Join-Path $node 'config/watchtower.settings.json') -Text '{"schema":"watchtower.settings.v1","service_bindings":[{"service_id":"live-state-surgeon","producer":"lss-dev","producer_instance":"instance-a"}]}'
    foreach ($name in @('pkt-hb-node-ok', 'pkt-hr-node-ok', 'pkt-pa-node-drift')) { Copy-WtTree -Source (Join-Path $fixtures $name) -Destination (Join-Path $node ('packets/inbox/' + $name)) }
    $run = Invoke-WtIngest -Root $node -VerificationTime '2026-03-12T15:05:00Z'
    Assert-WtEqual 3 $run.Accepted (@($run.Results | ForEach-Object { $_.PacketRef + ' ' + $_.Code }) -join '; ')
    Assert-WtEqual 0 $run.Rejected
    $rows = Get-Rows (Join-Path $node 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson')
    Assert-WtEqual 'ok,ok,ok' (($rows | ForEach-Object { $_['verify_result'] }) -join ',')
    Assert-WtEqual 'noncompliant' ($rows | Where-Object { $_['event_type'] -ceq 'watchtower.policy_attest.v1' })['compliance']
    Assert-WtTrue (Test-Path -LiteralPath (Join-Path $node 'runtime/devices/11111111-1111-1111-1111-111111111111/health_report.json'))
    Assert-WtEqual 1 @([System.IO.Directory]::GetFiles((Join-Path $node 'runtime/services/live-state-surgeon'), 'health_report_*.json')).Count
    $alerts = Get-Rows (Join-Path $node 'proofs/alerts/watchtower.alert.v1.ndjson')
    Assert-WtEqual 'POLICY_NONCOMPLIANT' $alerts[0]['alert_type']
    Assert-WtTrue (Test-WtLedger -Root $node).Valid
}

# --- NFL handoff (legacy v1 consumer, registry integration watchtower > nfl) ---------------------
function New-Handoff {
    param([string]$Name, [switch]$Incomplete)
    $dir = Join-Path $work $Name
    New-WtDirectory (Join-Path $dir 'frozen')
    Write-WtText -Path (Join-Path $dir 'WATCHTOWER_HANDOFF_MANIFEST.json') -Text '{"schema":"watchtower.handoff.manifest.v1","source_instrument":"NFL","source_role":"witness-only","release_tag":"nfl-tier0-test"}'
    $names = @('nfl.tier0.selftest.v1.ndjson', 'selftest_verify_packet.stdout.txt', 'selftest_verify_packet.stderr.txt', 'selftest_vectors.stdout.txt', 'selftest_vectors.stderr.txt', 'sha256sums.txt')
    if ($Incomplete) { $names = $names[0..4] }
    foreach ($file in $names) { Write-WtText -Path (Join-Path $dir ('frozen/' + $file)) -Text ('content of ' + $file) }
    $sums = New-Object System.Text.StringBuilder
    foreach ($file in @(Get-ChildItem -LiteralPath $dir -Recurse -File | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($dir.Length + 1).Replace('\', '/')
        [void]$sums.Append((Get-WtSha256 -Path $file.FullName)).Append('  ').Append($relative).Append("`n")
    }
    Write-WtText -Path (Join-Path $dir 'sha256sums.txt') -Text $sums.ToString()
    return $dir
}
Invoke-WtTest 'nfl handoff: the legacy consumer writes one integration receipt per run, failed runs included' {
    $node = Join-Path $work 'handoff-node'
    New-WtDirectory $node
    $script = Join-Path $repo 'scripts/watchtower_consume_nfl_handoff_v1.ps1'
    $ok = Invoke-WtChildPowerShell -File $script -Arguments @('-RepoRoot', $node, '-HandoffDir', (New-Handoff 'handoff-ok'))
    Assert-WtEqual 0 $ok.ExitCode $ok.Output
    Assert-WtTrue ($ok.Output -match 'WATCHTOWER_CONSUME_NFL_OK') $ok.Output
    $bad = Invoke-WtChildPowerShell -File $script -Arguments @('-RepoRoot', $node, '-HandoffDir', (New-Handoff 'handoff-bad' -Incomplete))
    Assert-WtTrue ($bad.ExitCode -ne 0) $bad.Output
    $missing = Invoke-WtChildPowerShell -File $script -Arguments @('-RepoRoot', $node, '-HandoffDir', (Join-Path $work 'no-handoff'))
    Assert-WtTrue ($missing.ExitCode -ne 0) $missing.Output
    $rows = Get-Rows (Join-Path $node 'proofs/integrations/watchtower__nfl.ndjson')
    Assert-WtEqual 'ok,failed,unavailable' (($rows | ForEach-Object { $_['outcome'] }) -join ',')
    Assert-WtEqual 'NFL_HANDOFF_FROZEN_REQUIRED_MISSING' $rows[1]['error_token']
    Assert-WtEqual (Get-WtSha256 -Path (Join-Path $work 'handoff-ok/WATCHTOWER_HANDOFF_MANIFEST.json')) $rows[0]['response_sha256']
    Assert-WtEqual 'nfl.tier0.selftest.v1' $rows[0]['contract']
    Assert-WtEqual $null $rows[2]['response_sha256']
}

# --- CLI ----------------------------------------------------------------------------------------
Invoke-WtTest 'cli: enroll -FromBundle and integrations -Witness print their tokens' {
    $node = New-Node 'cli'
    $source = New-NeverLostSource 'cli-source'
    $cli = Join-Path $repo 'bin/watchtower.ps1'
    $enroll = Invoke-WtChildPowerShell -File $cli -Arguments @('enroll', '-Root', $node, '-FromBundle', $source.Bundle, '-Principal', 'single-tenant/device_agent/device/lss-07')
    Assert-WtEqual 0 $enroll.ExitCode $enroll.Output
    Assert-WtTrue ($enroll.Output -match 'WATCHTOWER_ENROLL_OK') $enroll.Output
    $witness = Invoke-WtChildPowerShell -File $cli -Arguments @('integrations', '-Root', $node, '-Witness', '-VerificationTime', '2026-10-15T12:00:00Z')
    Assert-WtEqual 0 $witness.ExitCode $witness.Output
    Assert-WtTrue ($witness.Output -match 'witness_packet_id=[0-9a-f]{64}') $witness.Output
    Assert-WtTrue ($witness.Output -match 'WATCHTOWER_INTEGRATIONS_OK') $witness.Output
    Add-Content -LiteralPath (Join-Path $node 'proofs/integrations/watchtower__neverlost.ndjson') -Value 'x' -NoNewline
    $broken = Invoke-WtChildPowerShell -File $cli -Arguments @('integrations', '-Root', $node)
    Assert-WtEqual 1 $broken.ExitCode
    Assert-WtTrue ($broken.Output -match 'WATCHTOWER_INTEGRATIONS_FAIL:LEDGER_INTEGRATION_INVALID') $broken.Output
}

Remove-Item Env:WATCHTOWER_ARBITER_ROOT -ErrorAction SilentlyContinue
Remove-WtTree $work
Complete-WtTestSuite 'WATCHTOWER_INTEGRATION_TESTS'
