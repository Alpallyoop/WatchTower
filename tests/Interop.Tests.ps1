# Cross-repository conformance, run against the other services' real code and output.
#
#   live-state-surgeon  its current emitter, producing fresh packets that WatchTower ingests
#   CPR                 its actual verify_packet_v1.ps1 on WatchTower's NFL outbox packets
#   NeverLost           its actual trust-bundle reader, v1 verifier and allowed_signers writer
#   Arbiter             its actual evaluator behind WatchTower's policy gate, and `arbiter verify`
#
# Sibling checkouts are located through WATCHTOWER_<NAME>_ROOT or next to this repository. A
# missing sibling is reported as CASE_SKIP (unavailable), never as a pass; this suite is
# separate from the standalone Tier-0 gate on purpose. Sibling checkouts are never written:
# CPR runs from a temporary copy, the others only read their own files.
. (Join-Path $PSScriptRoot 'support/TestHarness.ps1')
. (Join-Path $PSScriptRoot 'support/ReferenceProducer.ps1')
$repo = Get-WtRepoRoot
$module = Import-Module (Join-Path $repo 'src/WatchTower/WatchTower.psd1') -Force -PassThru
$work = New-WtTempDirectory 'wt_interop_tests'

function Find-Sibling {
    param([string]$EnvironmentVariable, [string[]]$Names, [string]$Marker)
    $candidates = New-Object System.Collections.Generic.List[string]
    $fromEnvironment = [Environment]::GetEnvironmentVariable($EnvironmentVariable)
    if ($fromEnvironment) { $candidates.Add($fromEnvironment) }
    foreach ($name in $Names) { $candidates.Add((Join-Path (Split-Path -Parent $repo) $name)) }
    foreach ($candidate in $candidates) { if (Test-Path -LiteralPath (Join-Path $candidate $Marker) -PathType Leaf) { return (Resolve-Path -LiteralPath $candidate).Path } }
    return ''
}
function Test-WtWindowsHost { return ([System.IO.Path]::DirectorySeparatorChar -eq '\') }
$cprRoot = Find-Sibling 'WATCHTOWER_CPR_ROOT' @('cpr', 'CPR') 'scripts/verify_packet_v1.ps1'
$neverlostRoot = Find-Sibling 'WATCHTOWER_NEVERLOST_ROOT' @('neverlost', 'NeverLost') 'scripts/_lib_neverlost_v1.ps1'
$arbiterRoot = Find-Sibling 'WATCHTOWER_ARBITER_ROOT' @('arbiter', 'Arbiter') 'scripts/evaluate_arbiter_v1.ps1'
$lssRoot = Find-Sibling 'WATCHTOWER_LSS_ROOT' @('live-state-surgeon', '../_Atlas-Systems/live-state-surgeon') 'scripts/lss_emit_telemetry_packet_v1.ps1'

# A WatchTower node with an enrolled reference producer (NeverLost principal form) and one ingest run.
$producerPrincipal = 'single-tenant/device_agent/device/lss-reference'
$producerKey = New-ReferenceProducerKey -Directory (Join-Path $work 'keys') -Name 'producer'
$node = Join-Path $work 'node'
New-WtDirectory $node
[void](Initialize-WtTrust -Root $node -CreatedUtc '2026-10-13T00:00:00Z')
[void](Register-WtProducer -Root $node -Principal $producerPrincipal -KeyId 'lss-reference-ed25519' -PublicKey ($producerKey + '.pub'))
[void](New-ReferenceTelemetryPacket -Directory (Join-Path $node 'packets/inbox/hb') -KeyPath $producerKey -EventType 'watchtower.heartbeat.v1' -Principal $producerPrincipal)
[void](New-ReferenceTelemetryPacket -Directory (Join-Path $node 'packets/inbox/hr') -KeyPath $producerKey -EventType 'watchtower.health_report.v1' -Seq 2 -ProducerTime '2026-10-13T12:01:00Z' -Principal $producerPrincipal)
$run = Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:05:00Z'
$outboxPacket = Join-Path $node ('packets/outbox/' + $run.OutboxPacketId)

# --- live-state-surgeon: its current emitter ------------------------------------------------
Invoke-WtTest 'lss: packets emitted now by live-state-surgeon''s own emitter are accepted end to end' {
    if (-not $lssRoot) { Skip-WtTest 'live-state-surgeon checkout unavailable (set WATCHTOWER_LSS_ROOT)' }
    # ssh-keygen refuses a private key other users can read; sign with a protected copy of LSS's dev key.
    $keys = Join-Path $work 'lss-keys'
    New-WtDirectory $keys
    $key = Join-Path $keys 'lss_dev_ed25519'
    Copy-Item -LiteralPath (Join-Path $lssRoot 'keys/lss_dev_ed25519') -Destination $key
    Copy-Item -LiteralPath (Join-Path $lssRoot 'keys/lss_dev_ed25519.pub') -Destination ($key + '.pub')
    if (Test-WtWindowsHost) { & $module { param($k) Protect-WtPrivateKey -Path $k } $key } else { & chmod 600 $key }
    $lssNode = Join-Path $work 'lss-node'
    New-WtDirectory $lssNode
    [void](Initialize-WtTrust -Root $lssNode -CreatedUtc '2026-03-12T00:00:00Z')
    [void](Register-WtProducer -Root $lssNode -Principal 'lss-dev' -KeyId 'lss-dev-ed25519' -PublicKey ($key + '.pub'))
    $fixtures = Join-Path $lssRoot 'test_vectors/lss_live_visibility_v1/fixtures'
    $specs = @(@('hb-node-ok', 'watchtower.heartbeat.v1', '2026-03-12T15:04:00Z'), @('hr-node-ok', 'watchtower.health_report.v1', '2026-03-12T15:04:10Z'), @('pa-node-drift', 'watchtower.policy_attest.v1', '2026-03-12T15:04:10Z'))
    foreach ($spec in $specs) {
        $out = Join-Path $lssNode ('packets/inbox/pkt-' + $spec[0])
        $emit = Invoke-WtChildPowerShell -File (Join-Path $lssRoot 'scripts/lss_emit_telemetry_packet_v1.ps1') -Arguments @(
            '-RepoRoot', $lssRoot, '-EventType', $spec[1], '-FixturePath', (Join-Path $fixtures ($spec[0] + '.json')), '-OutRoot', $out, '-CreatedUtc', $spec[2], '-KeyPath', $key)
        Assert-WtEqual 0 $emit.ExitCode $emit.Output
        Assert-WtTrue ($emit.Output -match 'LSS_EMIT_PACKET_OK') $emit.Output
        # The vendored fixture is exactly what the current emitter produces (Ed25519 signatures are deterministic).
        Assert-WtEqual (Get-WtSha256 -Path (Join-Path $repo ('tests/fixtures/interop/live-state-surgeon/pkt-' + $spec[0] + '/sha256sums.txt'))) (Get-WtSha256 -Path (Join-Path $out 'sha256sums.txt')) ('fixture drift ' + $spec[0])
    }
    $lssRun = Invoke-WtIngest -Root $lssNode -VerificationTime '2026-03-12T15:05:00Z'
    Assert-WtEqual 3 $lssRun.Accepted (@($lssRun.Results | ForEach-Object { $_.PacketRef + ' ' + $_.Code }) -join '; ')
    Assert-WtTrue (Test-WtLedger -Root $lssNode).Valid
}

# --- CPR: its real verifier on WatchTower's outbox packets ---------------------------------
function Invoke-Cpr {
    param([string]$PacketPath)
    # CPR verify appends a receipt inside its own repository, so it always runs from a
    # temporary copy (the CPR checkout is never written). On non-Windows hosts CPR's
    # Uri-based relative-path helper throws for every packet, so that one helper is
    # replaced by an equivalent; every packet rule runs unmodified.
    if (-not $script:cprCopy) {
        $script:cprCopy = Join-Path $work 'cpr'
        Copy-Item -LiteralPath $cprRoot -Destination $script:cprCopy -Recurse
        if (-not (Test-WtWindowsHost)) {
            Add-Content -LiteralPath (Join-Path $script:cprCopy 'scripts/_lib_cpr_v1.ps1') -Value ("`nfunction Get-RelativePathNormalized([string]`$BasePath,[string]`$TargetPath){ " +
                "return [System.IO.Path]::GetRelativePath([System.IO.Path]::GetFullPath(`$BasePath),[System.IO.Path]::GetFullPath(`$TargetPath)).Replace('\','/') }")
        }
    }
    # The same PowerShell edition this suite runs under.
    $run = Invoke-WtChildPowerShell -File (Join-Path $script:cprCopy 'scripts/verify_packet_v1.ps1') -Arguments @('-RepoRoot', $script:cprCopy, '-PacketPath', $PacketPath)
    return [pscustomobject]@{ ExitCode = $run.ExitCode; Output = $run.Output.Trim() }
}
$script:cprCopy = ''

Invoke-WtTest 'cpr: accepts the NFL outbox packet WatchTower publishes (NFL witnesses only after CPR_VERIFY_OK)' {
    if (-not $cprRoot) { Skip-WtTest 'CPR checkout unavailable (set WATCHTOWER_CPR_ROOT)' }
    $result = Invoke-Cpr $outboxPacket
    Assert-WtEqual 0 $result.ExitCode $result.Output
    Assert-WtTrue ($result.Output -match 'CPR_VERIFY_OK') $result.Output
}
Invoke-WtTest 'cpr: rejects a tampered copy of that packet, as WatchTower does' {
    if (-not $cprRoot) { Skip-WtTest 'CPR checkout unavailable (set WATCHTOWER_CPR_ROOT)' }
    $copy = Join-Path $work 'tampered-outbox'
    Copy-WtTree -Source $outboxPacket -Destination $copy
    Add-Content -LiteralPath (Join-Path $copy 'payload/transcript_slice.ndjson') -Value 'x' -NoNewline
    $result = Invoke-Cpr $copy
    Assert-WtTrue ($result.Output -match 'CPR_VERIFY_FAIL:SHA256_MISMATCH') $result.Output
    Assert-WtEqual 'SHA256_MISMATCH' (Test-WtPacket $copy).Code
}
Invoke-WtTest 'cpr: accepts the integration-receipt witness packet WatchTower publishes for NFL' {
    if (-not $cprRoot) { Skip-WtTest 'CPR checkout unavailable (set WATCHTOWER_CPR_ROOT)' }
    $witnessNode = Join-Path $work 'witness-node'
    Copy-WtTree -Source $node -Destination $witnessNode
    $layout = & $module { param($r) Get-WtLayout $r } $witnessNode
    [void](& $module { param($l) Add-WtIntegrationReceipt -Layout $l -Receipt (New-WtIntegrationReceipt -Provider 'neverlost' -Contract 'neverlost.trust_bundle.v1' -ResponseSha256 ('e' * 64) -Outcome 'ok') } $layout)
    $published = Publish-WtIntegrationReceipts -Root $witnessNode -VerificationTime '2026-10-13T12:06:00Z'
    $result = Invoke-Cpr (Join-Path $witnessNode ('packets/outbox/' + $published.PacketId))
    Assert-WtEqual 0 $result.ExitCode $result.Output
    Assert-WtTrue ($result.Output -match 'CPR_VERIFY_OK') $result.Output
}
Invoke-WtTest 'cpr: WatchTower and CPR agree on every CPR golden vector' {
    if (-not $cprRoot) { Skip-WtTest 'CPR checkout unavailable (set WATCHTOWER_CPR_ROOT)' }
    $vectors = Join-Path $cprRoot 'test_vectors/packet_constitution_v1'
    $cases = @(@('minimal', 'OK'), @('negative/manifest_contains_packet_id', 'MANIFEST_CONTAINS_PACKET_ID'), @('negative/packet_id_mismatch', 'PACKET_ID_MISMATCH'), @('negative/sha256_mismatch', 'SHA256_MISMATCH'))
    foreach ($case in $cases) {
        # CPR's selftest copies only the packet files (the vector folder also holds expected_* fixtures).
        $packet = Join-Path $work ('vector-' + $case[0].Replace('/', '-'))
        New-WtDirectory $packet
        foreach ($name in @('manifest.json', 'packet_id.txt', 'sha256sums.txt')) { Copy-Item -LiteralPath (Join-Path $vectors ($case[0] + '/' + $name)) -Destination $packet }
        Copy-Item -LiteralPath (Join-Path $vectors ($case[0] + '/payload')) -Destination (Join-Path $packet 'payload') -Recurse
        $cpr = Invoke-Cpr $packet
        $cprCode = $(if ($cpr.Output -match 'CPR_VERIFY_OK') { 'OK' } elseif ($cpr.Output -match 'CPR_VERIFY_FAIL:([A-Z0-9_]+)') { $Matches[1] } else { 'UNKNOWN' })
        Assert-WtEqual $case[1] $cprCode ('CPR on ' + $case[0])
        Assert-WtEqual $case[1] (Test-WtPacket $packet).Code ('WatchTower on ' + $case[0])
    }
}

# --- NeverLost: its real trust-bundle code --------------------------------------------------
# WatchTower's bundle in NeverLost's layout: <root>/proofs/trust/trust_bundle.json, with every
# key file at its pubkey_path (relative to the same root, exactly as in WatchTower's state root).
$nl = Join-Path $work 'neverlost-root'
New-WtDirectory (Join-Path $nl 'proofs/trust')
Copy-Item -LiteralPath (Join-Path $node 'proofs/trust/neverlost/trust_bundle.json') -Destination (Join-Path $nl 'proofs/trust/trust_bundle.json')
foreach ($entry in (Read-WtJsonFile -Path (Join-Path $node 'proofs/trust/neverlost/trust_bundle.json') -Object)['principals']) {
    foreach ($key in $entry['keys']) {
        $target = Join-Path $nl ([string]$key['pubkey_path'])
        New-WtDirectory ([System.IO.Path]::GetDirectoryName($target))
        Copy-Item -LiteralPath (Join-Path $node ([string]$key['pubkey_path'])) -Destination $target
    }
}
Invoke-WtTest 'neverlost: its allowed_signers writer produces byte-identical output from WatchTower''s bundle' {
    if (-not $neverlostRoot) { Skip-WtTest 'NeverLost checkout unavailable (set WATCHTOWER_NEVERLOST_ROOT)' }
    $written = & {
        param($lib, $root)
        . $lib
        NL-WriteAllowedSignersFromTrust $root
    } (Join-Path $neverlostRoot 'scripts/_lib_neverlost_v1.ps1') $nl
    Assert-WtEqual (Get-WtSha256 -Path (Join-Path $node 'proofs/trust/neverlost/allowed_signers')) (Get-WtSha256 -Path ([string]@($written)[-1]))
}
Invoke-WtTest 'neverlost: its reader finds the WatchTower principal first with exactly the four registered namespaces' {
    if (-not $neverlostRoot) { Skip-WtTest 'NeverLost checkout unavailable (set WATCHTOWER_NEVERLOST_ROOT)' }
    $entries = & {
        param($lib, $root)
        . $lib
        $info = NL-LoadTrustBundleInfoV1 $root
        @(NL-GetTrustBundleEntriesCompat $info.Obj)
    } (Join-Path $neverlostRoot 'scripts/_lib_neverlost_v1.ps1') $nl
    Assert-WtEqual 'single-tenant/watchtower_authority/authority/watchtower' ([string]$entries[0].principal)
    Assert-WtEqual 'nfl/ingest-receipt,packet/envelope,watchtower,watchtower/device-pledge' ((@($entries[0].namespaces) | Sort-Object) -join ',')
}
Invoke-WtTest 'neverlost: its fail-closed v1 verifier accepts WatchTower''s bundle, key files and all' {
    if (-not $neverlostRoot) { Skip-WtTest 'NeverLost checkout unavailable (set WATCHTOWER_NEVERLOST_ROOT)' }
    $entries = & {
        param($lib, $root)
        . $lib
        if (-not (Get-Command NL-AssertTrustBundleV1 -ErrorAction SilentlyContinue)) { return $null }
        @(NL-AssertTrustBundleV1 -RepoRoot $root -ExpectedPrincipal 'single-tenant/watchtower_authority/authority/watchtower' -ExpectedNamespaces @('nfl/ingest-receipt', 'packet/envelope', 'watchtower', 'watchtower/device-pledge'))
    } (Join-Path $neverlostRoot 'scripts/_lib_neverlost_v1.ps1') $nl
    if ($null -eq $entries) { Skip-WtTest 'this NeverLost checkout predates NL-AssertTrustBundleV1 (branch audit/constellation-readiness-2026-10-15)' }
    Assert-WtEqual 2 @($entries).Count
    Assert-WtEqual 'lss-reference-ed25519' ([string]@($entries | Where-Object { $_.principal -ceq $producerPrincipal })[0].key_id)
}

# --- Arbiter: its real evaluator behind WatchTower's policy gate ----------------------------
function New-GatedNode {
    param([string]$Name)
    $gated = Join-Path $work $Name
    New-WtDirectory $gated
    [void](Initialize-WtTrust -Root $gated -CreatedUtc '2026-10-13T00:00:00Z')
    [void](Register-WtProducer -Root $gated -Principal $producerPrincipal -KeyId 'lss-reference-ed25519' -PublicKey ($producerKey + '.pub'))
    New-WtDirectory (Join-Path $gated 'config/arbiter/rules')
    Copy-Item -LiteralPath (Join-Path $repo 'config/arbiter/watchtower_ingest.policyset.json') -Destination (Join-Path $gated 'config/arbiter/')
    Copy-Item -LiteralPath (Join-Path $repo 'config/arbiter/rules/telemetry.rules.json') -Destination (Join-Path $gated 'config/arbiter/rules/')
    Write-WtText -Path (Join-Path $gated 'config/watchtower.settings.json') -Text '{"schema":"watchtower.settings.v1","arbiter":{"policyset":"config/arbiter/watchtower_ingest.policyset.json","policy_root":"config/arbiter"}}'
    return $gated
}
Invoke-WtTest 'arbiter: Arbiter validates the example policy WatchTower ships' {
    if (-not $arbiterRoot) { Skip-WtTest 'Arbiter checkout unavailable (set WATCHTOWER_ARBITER_ROOT)' }
    $r = Invoke-WtChildPowerShell -File (Join-Path $arbiterRoot 'scripts/arbiter.ps1') -Arguments @('validate', (Join-Path $repo 'config/arbiter/watchtower_ingest.policyset.json'), '--root', (Join-Path $repo 'config/arbiter'))
    Assert-WtEqual 0 $r.ExitCode $r.Output
    Assert-WtTrue ($r.Output -match 'VALID policyset') $r.Output
}
Invoke-WtTest 'arbiter: the real engine allows fresh telemetry and quarantines stale telemetry; WatchTower routes on it' {
    if (-not $arbiterRoot) { Skip-WtTest 'Arbiter checkout unavailable (set WATCHTOWER_ARBITER_ROOT)' }
    $saved = $env:WATCHTOWER_ARBITER_ROOT
    $env:WATCHTOWER_ARBITER_ROOT = $arbiterRoot
    try {
        $gated = New-GatedNode 'arbiter-node'
        [void](New-ReferenceTelemetryPacket -Directory (Join-Path $gated 'packets/inbox/a') -KeyPath $producerKey -EventType 'watchtower.heartbeat.v1' -Principal $producerPrincipal -ProducerTime '2026-10-13T12:00:00Z' -Seq 1)
        $first = Invoke-WtIngest -Root $gated -VerificationTime '2026-10-13T12:05:00Z'
        [void](New-ReferenceTelemetryPacket -Directory (Join-Path $gated 'packets/inbox/b') -KeyPath $producerKey -EventType 'watchtower.heartbeat.v1' -Principal $producerPrincipal -ProducerTime '2026-10-13T12:01:00Z' -Seq 2 -EventId 'evt-b')
        $second = Invoke-WtIngest -Root $gated -VerificationTime '2026-10-25T12:05:00Z'
    }
    finally { $env:WATCHTOWER_ARBITER_ROOT = $saved }
    Assert-WtEqual 1 $first.Accepted (@($first.Results | ForEach-Object { $_.Code }) -join ',')
    Assert-WtEqual 'POLICY_QUARANTINE' $second.Results[0].Code
    $rows = @((Read-WtText (Join-Path $gated 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson')).TrimEnd("`n").Split("`n") | ForEach-Object { ConvertFrom-WtJson $_ })
    Assert-WtEqual 'R900_ALLOW_VERIFIED_TELEMETRY' $rows[0]['policy_decision']['matched_rule_id']
    Assert-WtEqual 'R030_QUARANTINE_STALE_OBSERVATION' $rows[1]['policy_decision']['matched_rule_id']
    Assert-WtEqual '1.0.0' $rows[0]['policy_decision']['engine_version']
    $note = Read-WtJsonFile -Path (Join-Path $gated 'packets/quarantine/b.rejection.json') -Object
    Assert-WtEqual 'route_to_quarantine,notify_operator' (@($note['obligations'] | ForEach-Object { $_['type'] }) -join ',')
    $ledger = Test-WtLedger -Root $gated
    Assert-WtTrue $ledger.Valid ('{0} {1}' -f $ledger.Code, $ledger.Detail)
    # `arbiter verify` re-proves every stored decision from WatchTower's evidence, re-evaluating it.
    foreach ($row in $rows) {
        $block = $row['policy_decision']
        $set = Join-Path $gated ('proofs/policy/sets/' + $block['policy_hash'].Substring(7))
        $verify = Invoke-WtChildPowerShell -File (Join-Path $arbiterRoot 'scripts/arbiter.ps1') -Arguments @('verify',
            (Join-Path $gated ('proofs/policy/decisions/' + $block['decision_hash'].Substring(7) + '.json')),
            '--policy', (Join-Path $set 'policyset.json'), '--input', (Join-Path $gated ('proofs/policy/inputs/' + $block['input_hash'].Substring(7) + '.json')), '--root', (Join-Path $set 'rules'))
        Assert-WtEqual 0 $verify.ExitCode $verify.Output
        Assert-WtTrue ($verify.Output -match 'VERIFY_OK') $verify.Output
    }
}

Remove-WtTree $work
Complete-WtTestSuite 'WATCHTOWER_INTEROP_TESTS'
