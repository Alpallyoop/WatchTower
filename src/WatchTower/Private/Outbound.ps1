# Outbound evidence produced at the end of an ingest run:
#   1. a signed checkpoint seal over the receipt ledger head (ledger.md);
#   2. a Receipt Artifact v1 packet in PCv1 Option A form in packets/outbox/<packet_id>,
#      which NFL polls and witnesses after CPR verification (AnchorMark duplication law);
#   3. a chained, signed device pledge binding (1) and (2) (AnchorMark local-pledge law).

function Add-WtSignedChainEntry {
    # Links + hashes the row, signs its canonical line, then appends it (sign first:
    # a ledger row is never written without its signature).
    param(
        [Parameter(Mandatory = $true)]$Chain, [Parameter(Mandatory = $true)]$Row, [Parameter(Mandatory = $true)]$Authority,
        [Parameter(Mandatory = $true)][string]$Namespace, [Parameter(Mandatory = $true)][string]$SignatureDirectory
    )
    $Row[$Chain.PrevField] = $Chain.Head
    if ($Row.Contains($Chain.HashField)) { $Row.Remove($Chain.HashField) }
    $hash = Get-WtHashChainEntryHash -Row $Row -HashField $Chain.HashField
    $Row[$Chain.HashField] = $hash
    New-WtAuthoritySignature -Authority $Authority -Namespace $Namespace -Text (Get-WtSignedLine $Row) -SignaturePath (Join-Path $SignatureDirectory ($hash + '.sig'))
    [void](Add-WtHashChainEntry -Chain $Chain -Row $Row)
    return $hash
}

function Add-WtCheckpoint {
    param(
        [Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Authority, [Parameter(Mandatory = $true)]$ReceiptChain,
        [Parameter(Mandatory = $true)]$AlertChain, [Parameter(Mandatory = $true)][int]$FirstIndex, [Parameter(Mandatory = $true)][int]$LastIndex,
        [Parameter(Mandatory = $true)][string]$VerifiedUtc
    )
    $chain = Open-WtHashChain -Path $Layout.CheckpointLedger -HashField 'checkpoint_hash' -PrevField 'prev_checkpoint_hash'
    $range = New-WtObject
    $range['first_index'] = $FirstIndex
    $range['last_index'] = $LastIndex
    $row = New-WtObject
    $row['schema'] = $script:WtCheckpointSchema
    $row['event_type'] = 'ledger.checkpoint.seal'
    $row['ledger'] = $script:WtReceiptSchema
    $row['transcript_head_hash'] = $ReceiptChain.Head
    $row['receipt_count'] = $ReceiptChain.Count
    $row['range'] = $range
    $row['alerts_head_hash'] = $AlertChain.Head
    $row['alert_count'] = $AlertChain.Count
    $row['checkpoint_time'] = $VerifiedUtc
    $row['verifier'] = $Authority.Principal
    $row['verifier_key_id'] = $Authority.KeyId
    $row['node_id'] = $Authority.NodeId
    [void](Add-WtSignedChainEntry -Chain $chain -Row $row -Authority $Authority -Namespace $script:WtNamespaceEvidence -SignatureDirectory $Layout.CheckpointSigs)
    return , $row
}

function New-WtReceiptPacket {
    # Receipt Artifact v1 (docs/receipt_artifact_v1.md) carried as a PCv1 Option A packet.
    #   receipt_id = sha256(canonical_json(receipt.json without receipt_id) + LF)
    #   signatures/receipt.ed25519.sig : over receipt_id + LF   (namespace 'watchtower')
    #   signatures/manifest.sig        : over manifest.json     (namespace 'packet/envelope')
    param(
        [Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Authority, [Parameter(Mandatory = $true)]$Settings,
        [Parameter(Mandatory = $true)]$ReceiptChain, [Parameter(Mandatory = $true)][int]$FirstIndex, [Parameter(Mandatory = $true)][int]$LastIndex,
        [Parameter(Mandatory = $true)]$Checkpoint, [Parameter(Mandatory = $true)][string]$VerifiedUtc
    )
    $slice = New-Object System.Text.StringBuilder
    for ($index = $FirstIndex; $index -le $LastIndex; $index++) {
        [void]$slice.Append((ConvertTo-WtCanonicalJson $ReceiptChain.Rows[$index - 1])).Append("`n")
    }
    $sliceText = $slice.ToString()
    $checkpointText = Get-WtSignedLine $Checkpoint
    $checkpointSignature = [System.IO.File]::ReadAllBytes((Join-Path $Layout.CheckpointSigs ([string]$Checkpoint['checkpoint_hash'] + '.sig')))

    $refs = New-Object System.Collections.ArrayList
    foreach ($ref in @(
            @('transcript_slice', 'payload/transcript_slice.ndjson', (Get-WtSha256 -Text $sliceText), 'application/x-ndjson'),
            @('checkpoint', 'payload/checkpoint.json', (Get-WtSha256 -Text $checkpointText), 'application/json'),
            @('checkpoint_signature', 'payload/checkpoint.json.sig', (Get-WtSha256 -Bytes $checkpointSignature), 'application/x-sshsig'))) {
        $item = New-WtObject
        $item['type'] = $ref[0]; $item['path'] = $ref[1]; $item['sha256'] = $ref[2]; $item['media_type'] = $ref[3]
        [void]$refs.Add($item)
    }
    $ledger = New-WtObject
    $ledger['name'] = $script:WtReceiptSchema
    $ledger['first_index'] = $FirstIndex
    $ledger['last_index'] = $LastIndex
    $ledger['head_hash'] = $ReceiptChain.Rows[$LastIndex - 1]['receipt_hash']
    $policyRef = New-WtObject
    $policyRef['type'] = $script:WtSettingsSchema
    $policyRef['sha256'] = Get-WtCanonicalHash $Settings

    $receipt = New-WtObject
    $receipt['schema_version'] = '1'
    $receipt['tenant_id'] = 'single-tenant'
    $receipt['kind'] = 'attestation_ingest'
    $receipt['refs'] = $refs
    $receipt['ledger'] = $ledger
    $receipt['policy_ref'] = $policyRef
    $receipt['created_at_utc'] = $VerifiedUtc
    $receipt['signer_principal'] = $Authority.Principal
    $receipt['signer_key_id'] = $Authority.KeyId
    $receiptId = Get-WtCanonicalHash $receipt
    $receipt['receipt_id'] = $receiptId
    $receiptText = (ConvertTo-WtCanonicalJson $receipt) + "`n"

    $payload = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::Ordinal)
    $payload['receipt.json'] = $receiptText
    $payload['transcript_slice.ndjson'] = $sliceText
    $payload['checkpoint.json'] = $checkpointText
    $payload['checkpoint.json.sig'] = $checkpointSignature
    $files = New-Object System.Collections.ArrayList
    foreach ($name in $payload.PSBase.Keys) {
        $item = New-WtObject
        $item['path'] = 'payload/' + $name
        $content = $payload[$name]
        if ($content -is [byte[]]) { $item['sha256'] = Get-WtSha256 -Bytes $content } else { $item['sha256'] = Get-WtSha256 -Text ([string]$content) }
        [void]$files.Add($item)
    }
    $manifest = New-WtObject
    $manifest['schema'] = $script:WtReceiptPacketSchema
    $manifest['constitution'] = 'packet_constitution_v1_option_a'
    $manifest['kind'] = 'telemetry_receipts'
    $manifest['producer'] = $Authority.Principal
    $manifest['producer_instance'] = $Authority.NodeId
    $manifest['created_time'] = $VerifiedUtc
    $manifest['receipt_id'] = $receiptId
    $manifest['files'] = $files

    $context = [pscustomobject]@{ Authority = $Authority; ReceiptId = $receiptId }
    $sign = {
        param([string]$Build, [string]$PacketId, $Context)
        $signatures = Join-Path $Build 'signatures'
        New-WtAuthoritySignature -Authority $Context.Authority -Namespace $script:WtNamespaceEvidence -Text ($Context.ReceiptId + "`n") -SignaturePath (Join-Path $signatures 'receipt.ed25519.sig')
        New-WtAuthoritySignature -Authority $Context.Authority -Namespace $script:WtNamespaceEnvelope -MessagePath (Join-Path $Build 'manifest.json') -SignaturePath (Join-Path $signatures 'manifest.sig')
    }
    return New-WtPacket -OutputDirectory $Layout.Outbox -Manifest $manifest -Payload $payload -Signatures $sign -SignatureContext $context
}

function Add-WtDevicePledge {
    param(
        [Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Authority, [Parameter(Mandatory = $true)]$ReceiptChain,
        [Parameter(Mandatory = $true)]$AlertChain, [Parameter(Mandatory = $true)][string]$CheckpointHash,
        [AllowEmptyString()][string]$OutboxPacketId, [Parameter(Mandatory = $true)][string]$VerifiedUtc
    )
    $chain = Open-WtHashChain -Path $Layout.PledgeLedger -HashField 'pledge_hash' -PrevField 'prev_pledge_hash'
    $row = New-WtObject
    $row['schema'] = $script:WtPledgeSchema
    $row['pledge_time'] = $VerifiedUtc
    $row['node_id'] = $Authority.NodeId
    $row['verifier'] = $Authority.Principal
    $row['verifier_key_id'] = $Authority.KeyId
    $row['receipts_head_hash'] = $ReceiptChain.Head
    $row['receipt_count'] = $ReceiptChain.Count
    $row['alerts_head_hash'] = $AlertChain.Head
    $row['alert_count'] = $AlertChain.Count
    $row['checkpoint_hash'] = $CheckpointHash
    $row['outbox_packet_id'] = $OutboxPacketId
    return Add-WtSignedChainEntry -Chain $chain -Row $row -Authority $Authority -Namespace $script:WtNamespacePledge -SignatureDirectory $Layout.PledgeSigs
}
