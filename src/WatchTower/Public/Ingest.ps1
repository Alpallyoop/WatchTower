function Invoke-WtIngest {
    <#
    .SYNOPSIS
        Verifies every telemetry packet in packets/inbox and records the outcome.
    .DESCRIPTION
        For each inbox packet (ordinal name order; names starting with '.' or '_' are
        in-progress drops and are skipped):
          1. Test-WtTelemetryPacket (stateless contract + pinned-trust signatures).
          2. Stateful rules against the verified receipt ledger: duplicate packet, replayed
             event, sequence replay/regression and time regression per producer stream, and
             future timestamps beyond max_future_skew_seconds.
          3. Append a watchtower.telemetry.receipt.v1 row (hash chained), THEN route the packet
             to packets/receipts/<packet_id> (accepted) or packets/quarantine/<name> (rejected,
             with a .rejection.json note). Packets are moved, never modified.
          4. Publish verified evidence and append alert evidence.
        When the run added receipts: a signed checkpoint seal, a Receipt Artifact v1 packet in
        packets/outbox/<packet_id> for NFL, and a signed device pledge. Finally the run record
        and the evidence index are written.
        Identical inputs, prior ledgers, settings and -VerificationTime produce byte-identical
        outputs. -VerificationTime defaults to now and is recorded in every artifact.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$VerificationTime = (Get-WtUtcNow)
    )
    $verifiedAt = ConvertFrom-WtUtcTime $VerificationTime 'VerificationTime'
    $layout = Get-WtLayout $Root
    $settings = Read-WtSettings $layout
    $bundle = Read-WtTrustBundle $layout.TrustBundle -Root $layout.Root
    $authority = Get-WtAuthority -Layout $layout -Bundle $bundle
    $gate = Read-WtPolicyGate -Layout $layout -Settings $settings
    foreach ($directory in @($layout.Inbox, $layout.Accepted, $layout.Quarantine, $layout.Outbox, [System.IO.Path]::GetDirectoryName($layout.LastIngest))) { New-WtDirectory $directory }

    $lock = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($layout.LastIngest), 'ingest.lock')
    try { $lockStream = New-Object System.IO.FileStream($lock, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None) }
    catch { throw (New-WtFailure 'INGEST_LOCKED' 'another ingest is running, or runtime/ingest.lock was left by a crash') }
    try {
        $receipts = Open-WtHashChain -Path $layout.ReceiptLedger -HashField 'receipt_hash' -PrevField 'prev_receipt_hash'
        $alerts = Open-WtHashChain -Path $layout.AlertLedger -HashField 'alert_hash' -PrevField 'prev_alert_hash'
        $state = Get-WtStreamState -Receipts $receipts
        $skew = [long]$settings['max_future_skew_seconds']
        $results = New-Object System.Collections.ArrayList
        $ignored = New-Object System.Collections.ArrayList

        $names = [string[]]@([System.IO.Directory]::GetFileSystemEntries($layout.Inbox) | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        [Array]::Sort($names, [System.StringComparer]::Ordinal)
        foreach ($name in $names) {
            $source = Join-Path $layout.Inbox $name
            if ($name.StartsWith('.') -or $name.StartsWith('_') -or -not [System.IO.Directory]::Exists($source)) { [void]$ignored.Add($name); continue }

            $verdict = Test-WtTelemetryPacket -Path $source -TrustBundle $bundle
            if ($verdict.Valid) { Set-WtStatefulVerdict -Verdict $verdict -State $state -VerifiedAt $verifiedAt -SkewSeconds $skew }
            $facts = Get-WtTelemetryFacts -Verdict $verdict -Settings $settings
            # Policy gate (optional): only fully verified packets reach Arbiter; anything but
            # allow, including any evaluator failure, is a rejection at stage 'policy'.
            $policy = $null
            if ($null -ne $gate -and $verdict.Valid) {
                $policy = Invoke-WtPolicyGate -Gate $gate -Layout $layout -Verdict $verdict -Facts $facts -Bundle $bundle -Authority $authority -VerifiedUtc $VerificationTime
                if ($policy.Decision -cne 'allow') {
                    $verdict.Valid = $false
                    $verdict.Code = $policy.Code
                    $verdict.Detail = 'WT_FAIL:' + $policy.Code + ': ' + $policy.Detail
                    $verdict.Stage = 'policy'
                }
            }
            $accepted = [bool]$verdict.Valid

            if ($accepted) {
                $destination = Join-Path $layout.Accepted $verdict.PacketId
                # Decide routing before the receipt is written, so a receipt never names a
                # destination the packet cannot be moved to.
                if (Test-Path -LiteralPath $destination) {
                    $accepted = $false
                    $verdict.Valid = $false
                    $verdict.Code = 'ACCEPTED_DESTINATION_EXISTS'
                    $verdict.Detail = 'WT_FAIL:ACCEPTED_DESTINATION_EXISTS: packets/receipts/' + $verdict.PacketId
                    $verdict.Stage = 'route'
                }
            }
            if (-not $accepted) { $destination = Get-WtFreePath (Join-Path $layout.Quarantine $name) }

            try {
                $row = New-WtReceiptRow -Verdict $verdict -Accepted $accepted -Facts $facts -Authority $authority -VerifiedUtc $VerificationTime `
                    -PacketRef $name -RoutedTo (Get-WtRootRelative $layout $destination) -Roots @($layout.Root, $source)
                if ($null -ne $policy) { $row['policy_decision'] = ConvertTo-WtPolicyBlock $policy }
                $row['prev_receipt_hash'] = $receipts.Head
                $row['receipt_id'] = Get-WtCanonicalHash $row
            }
            catch {
                $policy = $null
                # No single packet may stop the pipeline: if its receipt cannot be built from
                # what it claims, it is rejected with nothing taken from it but its name.
                $verdict = New-WtUnrecordableVerdict -Code 'RECEIPT_UNRECORDABLE'
                $accepted = $false
                $facts = Get-WtTelemetryFacts -Verdict $verdict -Settings $settings
                $destination = Get-WtFreePath (Join-Path $layout.Quarantine $name)
                $row = New-WtReceiptRow -Verdict $verdict -Accepted $false -Facts $facts -Authority $authority -VerifiedUtc $VerificationTime `
                    -PacketRef $name -RoutedTo (Get-WtRootRelative $layout $destination) -Roots @($layout.Root, $source)
                $row['prev_receipt_hash'] = $receipts.Head
                $row['receipt_id'] = Get-WtCanonicalHash $row
            }
            $receiptHash = Add-WtHashChainEntry -Chain $receipts -Row $row

            Invoke-WtFsRetry { [System.IO.Directory]::Move($source, $destination) }
            if (-not $accepted) {
                $note = New-WtObject
                $note['schema'] = 'watchtower.quarantine_note.v1'
                $note['packet_ref'] = $name
                $note['code'] = $verdict.Code
                $note['receipt_hash'] = $receiptHash
                $note['receipt_time'] = $VerificationTime
                if ($null -ne $policy -and $policy.Decision -cne 'allow') {
                    $note['policy_decision'] = $policy.Decision
                    $note['policy_decision_hash'] = $policy.DecisionHash
                    $note['obligations'] = @($policy.Obligations | ForEach-Object { Copy-WtJsonValue $_ })
                }
                Write-WtJsonFile -Path ($destination + '.rejection.json') -Value $note
            }
            else {
                Update-WtStreamState -State $state -Verdict $verdict
                if ($settings['publish']['device_evidence']) {
                    [void](Publish-WtDeviceEvidence -Layout $layout -Verdict $verdict -Authority $authority -ReceiptHash $receiptHash -VerifiedUtc $VerificationTime -Facts $facts)
                }
                if ($settings['publish']['service_health'] -and $verdict.EventType -ceq 'watchtower.health_report.v1') {
                    $serviceId = Get-WtServiceBinding -Settings $settings -Verdict $verdict
                    if ($serviceId) { [void](Publish-WtServiceHealth -Layout $layout -ServiceId $serviceId -Verdict $verdict -Authority $authority -ReceiptHash $receiptHash -VerifiedUtc $VerificationTime -Facts $facts) }
                }
            }
            foreach ($alert in (Get-WtAlertsFor -Verdict $verdict -Accepted $accepted -Facts $facts)) {
                [void](Add-WtAlertRecord -Chain $alerts -Alert $alert -Verdict $verdict -Authority $authority -ReceiptHash $receiptHash -VerifiedUtc $VerificationTime)
            }
            [void]$results.Add([pscustomobject]@{
                    PacketRef = $name; Accepted = $accepted; Code = $verdict.Code; PacketId = $verdict.PacketId
                    EventType = $verdict.EventType; RoutedTo = (Get-WtRootRelative $layout $destination); ReceiptHash = $receiptHash
                })
        }

        $summary = [pscustomobject]@{
            Processed = $results.Count; Accepted = @($results | Where-Object { $_.Accepted }).Count
            Rejected = @($results | Where-Object { -not $_.Accepted }).Count; Ignored = $ignored.ToArray()
            ReceiptHead = $receipts.Head; ReceiptCount = $receipts.Count; AlertHead = $alerts.Head; AlertCount = $alerts.Count
            CheckpointHash = ''; OutboxPacketId = ''; PledgeHash = ''; IntegrationWitnessPacketId = ''; IntegrationWitnessError = ''; Results = $results.ToArray()
        }
        # Sealing resumes from the ledgers, not from this run: if a previous run stopped after
        # appending receipts but before sealing, the unsealed range is sealed now, and a
        # checkpoint that never got its outbox packet and pledge gets them now.
        $checkpoints = Open-WtHashChain -Path $layout.CheckpointLedger -HashField 'checkpoint_hash' -PrevField 'prev_checkpoint_hash'
        $sealedCount = 0
        $checkpoint = $null
        if ($checkpoints.Count -gt 0) {
            $checkpoint = $checkpoints.Rows[$checkpoints.Count - 1]
            $sealedCount = [int]$checkpoint['receipt_count']
        }
        if ($receipts.Count -gt $sealedCount) {
            $checkpoint = Add-WtCheckpoint -Layout $layout -Authority $authority -ReceiptChain $receipts -AlertChain $alerts -FirstIndex ($sealedCount + 1) -LastIndex $receipts.Count -VerifiedUtc $VerificationTime
            $summary.CheckpointHash = [string]$checkpoint['checkpoint_hash']
        }
        if ($null -ne $checkpoint) {
            $pledges = Open-WtHashChain -Path $layout.PledgeLedger -HashField 'pledge_hash' -PrevField 'prev_pledge_hash'
            $pledged = $pledges.Count -gt 0 -and [string]$pledges.Rows[$pledges.Count - 1]['checkpoint_hash'] -ceq [string]$checkpoint['checkpoint_hash']
            if (-not $pledged) {
                $range = $checkpoint['range']
                $outboxPacketId = ''
                if ($settings['publish']['nfl_outbox']) {
                    $packet = New-WtReceiptPacket -Layout $layout -Authority $authority -Settings $settings -ReceiptChain $receipts `
                        -FirstIndex ([int]$range['first_index']) -LastIndex ([int]$range['last_index']) -Checkpoint $checkpoint -VerifiedUtc ([string]$checkpoint['checkpoint_time'])
                    $outboxPacketId = $packet.PacketId
                }
                if ($settings['publish']['device_pledge']) {
                    $summary.PledgeHash = Add-WtDevicePledge -Layout $layout -Authority $authority -ReceiptChain $receipts -AlertChain $alerts `
                        -CheckpointHash ([string]$checkpoint['checkpoint_hash']) -OutboxPacketId $outboxPacketId -VerifiedUtc $VerificationTime
                }
                $summary.OutboxPacketId = $outboxPacketId
            }
        }
        # Integration receipts (this run's and any left unwitnessed) go to NFL through the outbox.
        # Witnessing never blocks: a failure here is recorded in the run record and retried by
        # the next run (or `integrations -Witness`); receipts already written stay authoritative.
        if ($settings['publish']['nfl_outbox']) {
            try {
                $witness = Publish-WtIntegrationWitness -Layout $layout -Authority $authority -VerifiedUtc $VerificationTime
                if ($null -ne $witness) { $summary.IntegrationWitnessPacketId = $witness.PacketId }
            }
            catch { $summary.IntegrationWitnessError = Get-WtFailureCode $_ }
        }
        Write-WtJsonFile -Path $layout.LastIngest -Value (ConvertTo-WtIngestRecord -Summary $summary -VerifiedUtc $VerificationTime -Authority $authority)
        [void](Export-WtEvidenceIndex -Root $layout.Root -GeneratedUtc $VerificationTime)
        return $summary
    }
    finally {
        $lockStream.Dispose()
        Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue
    }
}
