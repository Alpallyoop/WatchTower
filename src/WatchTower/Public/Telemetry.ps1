function Test-WtTelemetryPacket {
    <#
    .SYNOPSIS
        Verifies one signed telemetry packet emitted by a producer such as live-state-surgeon.
    .DESCRIPTION
        Stateless verification of the inbound contract (docs/contracts/live-state-surgeon.md):
          1. PCv1 Option A structure (Test-WtPacket, CPR-conformant).
          2. manifest.json: packet.manifest.v1 / packet.telemetry.v1, payload descriptor,
             files[] matching every packet file except manifest.json, packet_id.txt,
             sha256sums.txt and signatures/packet.sig (a manifest cannot list its own signature).
          3. payload/telemetry_event.json: event_hash = sha256 of its raw bytes; strict JSON;
             watchtower.telemetry_event.v1 envelope; header consistent with the manifest.
          4. signatures/packet.sig over the raw manifest bytes (namespace watchtower/packet) and
             payload/telemetry_event.sig over the raw event bytes (per-type namespace), both
             verified against the PINNED trust bundle for header.producer + header.key_id.
             allowed_signers / trust_bundle / public keys shipped inside the packet are ignored.
          5. Body rules per event type, including recomputed posture and policy hashes.
        Stateful rules (replay, sequence, clock skew) are applied by Invoke-WtIngest.
        The packet is never modified.
    .OUTPUTS
        PSCustomObject describing the verdict; Valid is $true only when every check passed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$TrustBundle
    )
    $verdict = [pscustomobject]@{
        Valid = $false; Code = ''; Detail = ''; Stage = 'pcv1'; SignerVerified = $false
        PacketId = ''; PacketKind = ''; EventType = ''; EventHash = ''; EventId = ''
        Producer = ''; ProducerInstance = ''; KeyId = ''; Namespace = ''
        DeviceId = ''; ProducerTime = ''; Seq = [long]-1; Event = $null
    }
    try {
        $root = Resolve-WtFullPath $Path
        $structure = Test-WtPacket $root
        if (-not $structure.Valid) { throw (New-WtFailure $structure.Code $structure.Detail) }
        $verdict.PacketId = $structure.PacketId

        # 2. Manifest
        $verdict.Stage = 'manifest'
        $manifest = Read-WtJsonFile -Path (Join-Path $root 'manifest.json') -Object
        if ((Get-WtField $manifest 'schema' 'string' 'manifest') -cne $script:WtManifestSchema) { throw (New-WtFailure 'MANIFEST_SCHEMA' $manifest['schema']) }
        $verdict.PacketKind = Get-WtField $manifest 'packet_kind' 'string' 'manifest'
        if ($verdict.PacketKind -cne $script:WtPacketKindTelemetry) { throw (New-WtFailure 'PACKET_KIND_UNSUPPORTED' $verdict.PacketKind) }
        $verdict.Producer = Get-WtField $manifest 'producer' 'text' 'manifest'
        $verdict.ProducerInstance = Get-WtField $manifest 'producer_instance' 'text' 'manifest'
        [void](ConvertFrom-WtUtcTime (Get-WtField $manifest 'created_time' 'string' 'manifest') 'manifest.created_time')
        $descriptor = Get-WtField $manifest 'payload' 'object' 'manifest'
        $verdict.EventType = Get-WtField $descriptor 'event_type' 'text' 'manifest.payload'
        if (-not $script:WtEventNamespaces.Contains($verdict.EventType)) { throw (New-WtFailure 'EVENT_TYPE_UNSUPPORTED' $verdict.EventType) }
        if ((Get-WtField $descriptor 'event_schema' 'string' 'manifest.payload') -cne $script:WtEnvelopeSchema) { throw (New-WtFailure 'EVENT_SCHEMA_UNSUPPORTED' $descriptor['event_schema']) }
        $verdict.EventHash = Get-WtField $descriptor 'event_hash' 'string' 'manifest.payload'
        if (-not (Test-WtHex64 $verdict.EventHash)) { throw (New-WtFailure 'EVENT_HASH_FORMAT') }

        $declared = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($entry in (Get-WtField $manifest 'files' 'array' 'manifest')) {
            $relative = Get-WtField $entry 'path' 'text' 'manifest.files'
            Assert-WtSafeRelativePath $relative
            # A manifest cannot list its own signature: signatures/packet.sig signs the manifest
            # bytes (sha256sums.txt covers it instead).
            if ($relative -ceq 'signatures/packet.sig') { throw (New-WtFailure 'MANIFEST_LISTS_OWN_SIGNATURE') }
            if (-not $declared.Add($relative)) { throw (New-WtFailure 'MANIFEST_FILES_DUPLICATE' $relative) }
            if ($structure.Files -cnotcontains $relative) { throw (New-WtFailure 'MANIFEST_FILE_MISSING' $relative) }
            if ((Get-WtField $entry 'sha256' 'string' 'manifest.files') -cne (Get-WtSha256 -Path (Join-Path $root $relative))) { throw (New-WtFailure 'MANIFEST_FILE_HASH_MISMATCH' $relative) }
        }
        foreach ($file in $structure.Files) {
            if (@('manifest.json', 'packet_id.txt', 'sha256sums.txt', 'signatures/packet.sig') -ccontains $file) { continue }
            if (-not $declared.Contains($file)) { throw (New-WtFailure 'MANIFEST_FILES_INCOMPLETE' $file) }
        }
        foreach ($required in @(@('payload/telemetry_event.json', 'MISSING_EVENT'), @('payload/telemetry_event.sig', 'MISSING_EVENT_SIGNATURE'), @('signatures/packet.sig', 'MISSING_PACKET_SIGNATURE'))) {
            if ($structure.Files -cnotcontains $required[0]) { throw (New-WtFailure $required[1]) }
        }

        # 3. Event envelope
        $verdict.Stage = 'event'
        $eventPath = Join-Path $root 'payload/telemetry_event.json'
        if ((Get-WtSha256 -Path $eventPath) -cne $verdict.EventHash) { throw (New-WtFailure 'EVENT_HASH_MISMATCH') }
        try { $telemetryEvent = Read-WtJsonFile -Path $eventPath -Object }
        catch { throw (New-WtFailure 'EVENT_INVALID' (Get-WtFailureCode $_)) }
        $verdict.Event = $telemetryEvent
        if ((Get-WtField $telemetryEvent 'schema' 'string' 'event') -cne $script:WtEnvelopeSchema) { throw (New-WtFailure 'EVENT_SCHEMA_UNSUPPORTED' $telemetryEvent['schema']) }
        if ((Get-WtField $telemetryEvent 'event_type' 'string' 'event') -cne $verdict.EventType) { throw (New-WtFailure 'EVENT_TYPE_MISMATCH') }
        $header = Get-WtField $telemetryEvent 'header' 'object' 'event'
        $body = Get-WtField $telemetryEvent 'body' 'object' 'event'
        $verdict.EventId = Get-WtField $header 'event_id' 'text' 'header'
        $verdict.DeviceId = Get-WtField $header 'device_id' 'text' 'header'
        foreach ($identifier in @($verdict.EventId, $verdict.DeviceId)) {
            if ($identifier -cnotmatch $script:WtIdentifierPattern) { throw (New-WtFailure 'HEADER_IDENTIFIER_FORMAT' $identifier) }
        }
        if ((Get-WtField $header 'producer' 'text' 'header') -cne $verdict.Producer) { throw (New-WtFailure 'PRODUCER_MISMATCH') }
        if ((Get-WtField $header 'producer_instance' 'text' 'header') -cne $verdict.ProducerInstance) { throw (New-WtFailure 'PRODUCER_INSTANCE_MISMATCH') }
        $verdict.KeyId = Get-WtField $header 'key_id' 'text' 'header'
        $verdict.Namespace = Get-WtField $header 'namespace' 'text' 'header'
        if ($verdict.Namespace -cne $script:WtEventNamespaces[$verdict.EventType]) { throw (New-WtFailure 'NAMESPACE_MISMATCH' $verdict.Namespace) }
        $verdict.ProducerTime = Get-WtField $header 'producer_time' 'string' 'header'
        [void](ConvertFrom-WtUtcTime $verdict.ProducerTime 'header.producer_time')
        $verdict.Seq = [long](Get-WtField $header 'seq' 'int' 'header')
        if ($verdict.Seq -lt 0) { throw (New-WtFailure 'HEADER_SEQ_NEGATIVE') }

        # 4. Signatures against pinned trust
        $verdict.Stage = 'signature'
        $packetSignatureOk = Test-WtTrustedSignature -Bundle $TrustBundle -Principal $verdict.Producer -KeyId $verdict.KeyId -Namespace $script:WtNamespacePacket `
            -SignaturePath (Join-Path $root 'signatures/packet.sig') -MessagePath (Join-Path $root 'manifest.json')
        if (-not $packetSignatureOk) { throw (New-WtFailure 'PACKET_SIG_INVALID') }
        $eventSignatureOk = Test-WtTrustedSignature -Bundle $TrustBundle -Principal $verdict.Producer -KeyId $verdict.KeyId -Namespace $verdict.Namespace `
            -SignaturePath (Join-Path $root 'payload/telemetry_event.sig') -MessagePath $eventPath
        if (-not $eventSignatureOk) { throw (New-WtFailure 'EVENT_SIG_INVALID') }
        $verdict.SignerVerified = $true

        # 5. Body
        $verdict.Stage = 'body'
        Assert-WtTelemetryBody -EventType $verdict.EventType -Body $body

        $verdict.Valid = $true
        $verdict.Code = 'OK'
        $verdict.Stage = 'complete'
    }
    catch {
        $verdict.Code = Get-WtFailureCode $_
        $verdict.Detail = Get-WtFailureMessage $_
    }
    return $verdict
}
