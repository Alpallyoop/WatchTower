# bin/watchtower.ps1 as a separate process: tokens, exit codes and -Json output are the
# interface other services and runners depend on.
. (Join-Path $PSScriptRoot 'support/TestHarness.ps1')
. (Join-Path $PSScriptRoot 'support/ReferenceProducer.ps1')
$repo = Get-WtRepoRoot
$cli = Join-Path $repo 'bin/watchtower.ps1'
$exe = (Get-Process -Id $PID).Path
$work = New-WtTempDirectory 'wt_cli_tests'
$root = Join-Path $work 'node'
New-WtDirectory $root
$producerKey = New-ReferenceProducerKey -Directory (Join-Path $work 'keys') -Name 'producer'

function Invoke-Cli {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $cli @Arguments 2>&1 | Out-String
    $lines = @($output.Trim() -split "`r?`n")
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output; Token = $lines[$lines.Count - 1] }
}

function Assert-Cli {
    param($Result, [int]$ExitCode, [string]$Token)
    Assert-WtEqual $ExitCode $Result.ExitCode $Result.Output
    Assert-WtEqual $Token $Result.Token $Result.Output
}

Invoke-WtTest 'cli: version' { $r = Invoke-Cli version; Assert-Cli $r 0 'WATCHTOWER_VERSION_OK'; Assert-WtTrue ($r.Output -match 'version=2\.0\.0') $r.Output }
Invoke-WtTest 'cli: help exits 0' { Assert-WtEqual 0 (Invoke-Cli help).ExitCode }
Invoke-WtTest 'cli: unknown command fails closed' { Assert-Cli (Invoke-Cli frobnicate) 1 'WATCHTOWER_CLI_FAIL:UNKNOWN_COMMAND' }
Invoke-WtTest 'cli: missing state root fails closed' { Assert-Cli (Invoke-Cli ingest -Root (Join-Path $work 'absent')) 1 'WATCHTOWER_INGEST_FAIL:STATE_ROOT_MISSING' }
Invoke-WtTest 'cli: trust before init reports the missing bundle' { Assert-Cli (Invoke-Cli trust -Root $root) 1 'WATCHTOWER_TRUST_FAIL:TRUST_BUNDLE_MISSING' }
Invoke-WtTest 'cli: init, then trust' {
    Assert-Cli (Invoke-Cli init -Root $root -VerificationTime '2026-10-13T00:00:00Z') 0 'WATCHTOWER_INIT_OK'
    Assert-Cli (Invoke-Cli trust -Root $root) 0 'WATCHTOWER_TRUST_OK'
}
Invoke-WtTest 'cli: enroll validates arguments, then enrolls' {
    Assert-Cli (Invoke-Cli enroll -Root $root -Principal 'lss-reference') 1 'WATCHTOWER_ENROLL_FAIL:USAGE'
    $r = Invoke-Cli enroll -Root $root -Principal 'lss-reference' -KeyId 'lss-reference-ed25519' -PublicKey ($producerKey + '.pub')
    Assert-Cli $r 0 'WATCHTOWER_ENROLL_OK'
    Assert-WtTrue ($r.Output -match 'changed=True') $r.Output
}
$packet = New-ReferenceTelemetryPacket -Directory (Join-Path $work 'pkt') -KeyPath $producerKey -EventType 'watchtower.heartbeat.v1'
Invoke-WtTest 'cli: verify-packet and verify-telemetry accept a valid packet' {
    Assert-Cli (Invoke-Cli verify-packet $packet) 0 'WATCHTOWER_VERIFY_PACKET_OK'
    Assert-Cli (Invoke-Cli verify-telemetry $packet -Root $root) 0 'WATCHTOWER_VERIFY_TELEMETRY_OK'
}
Invoke-WtTest 'cli: verify-packet rejects a tampered packet with the CPR code' {
    $copy = Join-Path $work 'tampered'
    Copy-WtTree -Source $packet -Destination $copy
    Add-Content -LiteralPath (Join-Path $copy 'payload/telemetry_event.json') -Value 'x' -NoNewline
    Assert-Cli (Invoke-Cli verify-packet $copy) 1 'WATCHTOWER_VERIFY_PACKET_FAIL:SHA256_MISMATCH'
}
Invoke-WtTest 'cli: ingest -Json emits canonical JSON, then the token' {
    Copy-WtTree -Source $packet -Destination (Join-Path $root 'packets/inbox/hb')
    $r = Invoke-Cli ingest -Root $root -VerificationTime '2026-10-13T12:05:00Z' -Json
    Assert-Cli $r 0 'WATCHTOWER_INGEST_OK'
    $jsonLine = @($r.Output.Trim() -split "`r?`n")[0]
    $parsed = ConvertFrom-WtJson $jsonLine
    Assert-WtEqual $jsonLine (ConvertTo-WtCanonicalJson $parsed)
    Assert-WtEqual ([long]1) $parsed['accepted']
}
Invoke-WtTest 'cli: ledger, doctor -Publish and index succeed on a healthy node' {
    Assert-Cli (Invoke-Cli ledger -Root $root) 0 'WATCHTOWER_LEDGER_OK'
    Assert-Cli (Invoke-Cli doctor -Root $root -VerificationTime '2026-10-13T12:10:00Z' -Publish) 0 'WATCHTOWER_DOCTOR_OK'
    Assert-Cli (Invoke-Cli index -Root $root -VerificationTime '2026-10-13T12:10:00Z') 0 'WATCHTOWER_INDEX_OK'
}
Invoke-WtTest 'cli: ledger and doctor fail closed after tampering' {
    $ledger = Join-Path $root 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson'
    Write-WtText -Path $ledger -Text ((Read-WtText $ledger).Replace('"seq":1', '"seq":2'))
    Assert-Cli (Invoke-Cli ledger -Root $root) 1 'WATCHTOWER_LEDGER_FAIL:CHAIN_HASH_MISMATCH'
    Assert-Cli (Invoke-Cli doctor -Root $root -VerificationTime '2026-10-13T12:20:00Z') 1 'WATCHTOWER_DOCTOR_FAIL:CHAIN_HASH_MISMATCH'
}

Remove-WtTree $work
Complete-WtTestSuite 'WATCHTOWER_CLI_TESTS'
