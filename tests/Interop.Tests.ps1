# Cross-repository conformance, run against the other services' real code and output.
#
#   live-state-surgeon  its actual emitted packet (vendored fixture, see PROVENANCE.md)
#   CPR                 its actual verify_packet_v1.ps1 on WatchTower's NFL outbox packets
#   NeverLost           its actual trust-bundle reader and allowed_signers writer
#
# Sibling checkouts are located through WATCHTOWER_CPR_ROOT / WATCHTOWER_NEVERLOST_ROOT or
# next to this repository. A missing sibling is reported as CASE_SKIP (unavailable), never
# as a pass; this suite is separate from the standalone Tier-0 gate on purpose.
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
$cprRoot = Find-Sibling 'WATCHTOWER_CPR_ROOT' @('cpr', 'CPR') 'scripts/verify_packet_v1.ps1'
$neverlostRoot = Find-Sibling 'WATCHTOWER_NEVERLOST_ROOT' @('neverlost', 'NeverLost') 'scripts/_lib_neverlost_v1.ps1'

# A WatchTower node with an enrolled reference producer and one ingest run.
$producerKey = New-ReferenceProducerKey -Directory (Join-Path $work 'keys') -Name 'producer'
$node = Join-Path $work 'node'
New-WtDirectory $node
[void](Initialize-WtTrust -Root $node -CreatedUtc '2026-10-13T00:00:00Z')
[void](Register-WtProducer -Root $node -Principal 'lss-reference' -KeyId 'lss-reference-ed25519' -PublicKey ($producerKey + '.pub'))
[void](New-ReferenceTelemetryPacket -Directory (Join-Path $node 'packets/inbox/hb') -KeyPath $producerKey -EventType 'watchtower.heartbeat.v1')
[void](New-ReferenceTelemetryPacket -Directory (Join-Path $node 'packets/inbox/hr') -KeyPath $producerKey -EventType 'watchtower.health_report.v1' -Seq 2 -ProducerTime '2026-10-13T12:01:00Z')
$run = Invoke-WtIngest -Root $node -VerificationTime '2026-10-13T12:05:00Z'
$outboxPacket = Join-Path $node ('packets/outbox/' + $run.OutboxPacketId)

# --- live-state-surgeon: its real emitted packet ----------------------------------------------
$lssPacket = Join-Path $repo 'tests/fixtures/interop/live-state-surgeon/pkt-hb-node-ok'
$lssBundle = Copy-WtJsonValue ([ordered]@{
        schema = 'neverlost.trust_bundle.v1'; created_utc = '2026-10-13T00:00:00Z'
        principals = @([ordered]@{ principal = 'lss-dev'; keys = @([ordered]@{
                        key_id = 'lss-dev-ed25519'; alg = 'ssh-ed25519'; pubkey = (ConvertTo-WtPublicKey (Read-WtText (Join-Path $lssPacket 'signer_ed25519.pub')))
                        namespaces = @('watchtower/packet', 'watchtower/telemetry-alert', 'watchtower/telemetry-health', 'watchtower/telemetry-heartbeat', 'watchtower/telemetry-policy')
                    }) })
    })
Invoke-WtTest 'lss: the real packet satisfies PCv1 (raw-byte packet_id, full sha256sums coverage)' {
    $result = Test-WtPacket $lssPacket
    Assert-WtTrue $result.Valid ('{0} {1}' -f $result.Code, $result.Detail)
    Assert-WtEqual 'c21232b10a641c9b19733f67c68310a261799aac85af87ef1d555779c103cd31' $result.PacketId
}
Invoke-WtTest 'lss: with lss-dev enrolled, the packet is still rejected because its manifest lists its own signature' {
    $verdict = Test-WtTelemetryPacket -Path $lssPacket -TrustBundle $lssBundle
    Assert-WtTrue (-not $verdict.Valid)
    Assert-WtEqual 'MANIFEST_LISTS_OWN_SIGNATURE' $verdict.Code
}
Invoke-WtTest 'lss: the event layer is already compatible (envelope, namespace, signature, body rules)' {
    $event = Read-WtJsonFile -Path (Join-Path $lssPacket 'payload/telemetry_event.json') -Object -Canonical
    Assert-WtEqual 'watchtower.telemetry_event.v1' $event['schema']
    Assert-WtEqual 'watchtower/telemetry-heartbeat' $event['header']['namespace']
    $ok = & $module {
        param($bundle, $packet, $body)
        Assert-WtTelemetryBody -EventType 'watchtower.heartbeat.v1' -Body $body
        Test-WtTrustedSignature -Bundle $bundle -Principal 'lss-dev' -KeyId 'lss-dev-ed25519' -Namespace 'watchtower/telemetry-heartbeat' `
            -SignaturePath (Join-Path $packet 'payload/telemetry_event.sig') -MessagePath (Join-Path $packet 'payload/telemetry_event.json')
    } $lssBundle $lssPacket $event['body']
    Assert-WtTrue $ok 'event signature by lss-dev did not verify'
}
Invoke-WtTest 'lss: its packet.sig does not cover the manifest it ships (the emitter defect, proven)' {
    $ok = & $module {
        param($bundle, $packet)
        Test-WtTrustedSignature -Bundle $bundle -Principal 'lss-dev' -KeyId 'lss-dev-ed25519' -Namespace 'watchtower/packet' `
            -SignaturePath (Join-Path $packet 'signatures/packet.sig') -MessagePath (Join-Path $packet 'manifest.json')
    } $lssBundle $lssPacket
    Assert-WtTrue (-not $ok)
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
    $exe = (Get-Process -Id $PID).Path   # the same PowerShell edition this suite runs under
    $output = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $script:cprCopy 'scripts/verify_packet_v1.ps1') -RepoRoot $script:cprCopy -PacketPath $PacketPath 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output.Trim() }
}
function Test-WtWindowsHost { return ([System.IO.Path]::DirectorySeparatorChar -eq '\') }
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
Invoke-WtTest 'neverlost: its allowed_signers writer produces byte-identical output from WatchTower''s bundle' {
    if (-not $neverlostRoot) { Skip-WtTest 'NeverLost checkout unavailable (set WATCHTOWER_NEVERLOST_ROOT)' }
    $nl = Join-Path $work 'neverlost-root'
    New-WtDirectory (Join-Path $nl 'proofs/trust')
    Copy-Item -LiteralPath (Join-Path $node 'proofs/trust/neverlost/trust_bundle.json') -Destination (Join-Path $nl 'proofs/trust/trust_bundle.json')
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
    } (Join-Path $neverlostRoot 'scripts/_lib_neverlost_v1.ps1') (Join-Path $work 'neverlost-root')
    Assert-WtEqual 'single-tenant/watchtower_authority/authority/watchtower' ([string]$entries[0].principal)
    Assert-WtEqual 'nfl/ingest-receipt,packet/envelope,watchtower,watchtower/device-pledge' ((@($entries[0].namespaces) | Sort-Object) -join ',')
}

Remove-WtTree $work
Complete-WtTestSuite 'WATCHTOWER_INTEROP_TESTS'
