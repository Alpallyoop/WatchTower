function Test-WtLedger {
    <#
    .SYNOPSIS
        Re-verifies all WatchTower ledgers from their bytes.
    .DESCRIPTION
        Recomputes every hash link of the receipt, alert, checkpoint and pledge chains, verifies
        every checkpoint and pledge signature against the pinned authority key, and checks the
        cross-links: each checkpoint seals the receipt and alert heads it names, and each pledge
        binds an existing checkpoint and the receipt head at that point. Stored values are never
        trusted without recomputation.
    .OUTPUTS
        PSCustomObject: Valid, Code, Detail, Ledgers, Warnings
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$Root)
    $report = [pscustomobject]@{ Valid = $false; Code = ''; Detail = ''; Ledgers = $null; Warnings = (New-Object System.Collections.ArrayList) }
    try {
        $layout = Get-WtLayout $Root
        $bundle = Read-WtTrustBundle $layout.TrustBundle
        $receipts = Open-WtHashChain -Path $layout.ReceiptLedger -HashField 'receipt_hash' -PrevField 'prev_receipt_hash'
        $alerts = Open-WtHashChain -Path $layout.AlertLedger -HashField 'alert_hash' -PrevField 'prev_alert_hash'
        $checkpoints = Open-WtHashChain -Path $layout.CheckpointLedger -HashField 'checkpoint_hash' -PrevField 'prev_checkpoint_hash'
        $pledges = Open-WtHashChain -Path $layout.PledgeLedger -HashField 'pledge_hash' -PrevField 'prev_pledge_hash'

        $headAt = {
            param($Chain, [long]$Count)
            if ($Count -eq 0) { return 'GENESIS' }
            if ($Count -gt $Chain.Count) { return '' }
            return [string]$Chain.Rows[$Count - 1][$Chain.HashField]
        }

        foreach ($row in $receipts.Rows) {
            if ([string]$row['schema'] -cne $script:WtReceiptSchema) { throw (New-WtFailure 'LEDGER_RECEIPT_SCHEMA' $row['receipt_hash']) }
            if (@('ok', 'reject') -cnotcontains [string]$row['verify_result']) { throw (New-WtFailure 'LEDGER_RECEIPT_RESULT' $row['receipt_hash']) }
            if (-not (Test-Path -LiteralPath (Join-Path $layout.Root ([string]$row['routed_to'])))) { [void]$report.Warnings.Add('ROUTED_PACKET_ABSENT ' + $row['routed_to']) }
        }
        foreach ($row in $alerts.Rows) {
            if ([string]$row['schema'] -cne $script:WtAlertSchema) { throw (New-WtFailure 'LEDGER_ALERT_SCHEMA' $row['alert_hash']) }
        }
        $checkpointHashes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($row in $checkpoints.Rows) {
            $hash = [string]$row['checkpoint_hash']
            $signature = Join-Path $layout.CheckpointSigs ($hash + '.sig')
            if (-not (Test-WtAuthoritySignature -Bundle $bundle -Namespace $script:WtNamespaceEvidence -SignaturePath $signature -Text (Get-WtSignedLine $row))) { throw (New-WtFailure 'LEDGER_CHECKPOINT_SIGNATURE' $hash) }
            if ((& $headAt $receipts ([long]$row['receipt_count'])) -cne [string]$row['transcript_head_hash']) { throw (New-WtFailure 'LEDGER_CHECKPOINT_RECEIPTS' $hash) }
            if ((& $headAt $alerts ([long]$row['alert_count'])) -cne [string]$row['alerts_head_hash']) { throw (New-WtFailure 'LEDGER_CHECKPOINT_ALERTS' $hash) }
            [void]$checkpointHashes.Add($hash)
        }
        foreach ($row in $pledges.Rows) {
            $hash = [string]$row['pledge_hash']
            $signature = Join-Path $layout.PledgeSigs ($hash + '.sig')
            if (-not (Test-WtAuthoritySignature -Bundle $bundle -Namespace $script:WtNamespacePledge -SignaturePath $signature -Text (Get-WtSignedLine $row))) { throw (New-WtFailure 'LEDGER_PLEDGE_SIGNATURE' $hash) }
            if ((& $headAt $receipts ([long]$row['receipt_count'])) -cne [string]$row['receipts_head_hash']) { throw (New-WtFailure 'LEDGER_PLEDGE_RECEIPTS' $hash) }
            if (-not $checkpointHashes.Contains([string]$row['checkpoint_hash'])) { throw (New-WtFailure 'LEDGER_PLEDGE_CHECKPOINT' $hash) }
            $packetId = [string]$row['outbox_packet_id']
            if ($packetId) {
                $packetPath = Join-Path $layout.Outbox $packetId
                if (-not [System.IO.Directory]::Exists($packetPath)) { [void]$report.Warnings.Add('OUTBOX_PACKET_ABSENT ' + $packetId) }
                elseif (-not (Test-WtPacket $packetPath).Valid) { throw (New-WtFailure 'LEDGER_OUTBOX_PACKET_INVALID' $packetId) }
            }
        }
        $summary = { param($Chain) [pscustomobject]@{ Count = $Chain.Count; Head = $Chain.Head } }
        $report.Ledgers = [pscustomobject]@{
            Receipts = & $summary $receipts; Alerts = & $summary $alerts; Checkpoints = & $summary $checkpoints; Pledges = & $summary $pledges
        }
        $report.Valid = $true
        $report.Code = 'OK'
    }
    catch {
        $report.Code = Get-WtFailureCode $_
        $report.Detail = Get-WtFailureMessage $_
    }
    return $report
}
