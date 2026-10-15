# Stateful verification rules and receipt construction for Invoke-WtIngest.
# All state is derived from the verified receipt ledger; there is no separate,
# mutable state file that could drift from the evidence.

function Get-WtStreamKey {
    [OutputType([string])]
    param([string]$Producer, [string]$ProducerInstance, [string]$DeviceId)
    return $Producer + "`n" + $ProducerInstance + "`n" + $DeviceId
}

function Get-WtStreamState {
    param([Parameter(Mandatory = $true)]$Receipts)
    $state = [pscustomobject]@{
        Packets = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        Events  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        Streams = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
    }
    foreach ($row in $Receipts.Rows) {
        if ([string]$row['verify_result'] -cne 'ok') { continue }
        Update-WtStreamState -State $state -Verdict ([pscustomobject]@{
                PacketId = [string]$row['packet_id']; Producer = [string]$row['producer']; ProducerInstance = [string]$row['producer_instance']
                DeviceId = [string]$row['device_id']; EventId = [string]$row['event_id']; Seq = [long]$row['seq']; ProducerTime = [string]$row['producer_time']
            })
    }
    return $state
}

function Update-WtStreamState {
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)]$Verdict)
    [void]$State.Packets.Add($Verdict.PacketId)
    [void]$State.Events.Add($Verdict.Producer + "`n" + $Verdict.EventId)
    $State.Streams[(Get-WtStreamKey $Verdict.Producer $Verdict.ProducerInstance $Verdict.DeviceId)] = [pscustomobject]@{ Seq = [long]$Verdict.Seq; Time = $Verdict.ProducerTime }
}

function Set-WtStatefulVerdict {
    # Turns a statelessly valid verdict into a rejection when it violates replay,
    # ordering or clock rules. Signer identity stays verified (SignerVerified).
    param([Parameter(Mandatory = $true)]$Verdict, [Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][datetime]$VerifiedAt, [Parameter(Mandatory = $true)][long]$SkewSeconds)
    $code = ''
    $last = $null
    $streamKey = Get-WtStreamKey $Verdict.Producer $Verdict.ProducerInstance $Verdict.DeviceId
    if ($State.Streams.ContainsKey($streamKey)) { $last = $State.Streams[$streamKey] }
    if ($State.Packets.Contains($Verdict.PacketId)) { $code = 'DUPLICATE_PACKET' }
    elseif ($State.Events.Contains($Verdict.Producer + "`n" + $Verdict.EventId)) { $code = 'REPLAYED_EVENT' }
    elseif ($null -ne $last -and $Verdict.Seq -eq $last.Seq) { $code = 'SEQUENCE_REPLAYED' }
    elseif ($null -ne $last -and $Verdict.Seq -lt $last.Seq) { $code = 'SEQUENCE_REGRESSION' }
    elseif ($null -ne $last -and [string]::CompareOrdinal($Verdict.ProducerTime, $last.Time) -lt 0) { $code = 'TIME_REGRESSION' }
    elseif (((ConvertFrom-WtUtcTime $Verdict.ProducerTime) - $VerifiedAt).TotalSeconds -gt $SkewSeconds) { $code = 'FUTURE_TIMESTAMP' }
    if ($code) {
        $Verdict.Valid = $false
        $Verdict.Code = $code
        $Verdict.Detail = 'WT_FAIL:' + $code
        $Verdict.Stage = 'state'
    }
}

function Get-WtTelemetryFacts {
    # Facts consumers need, extracted only from signer-verified events.
    param([Parameter(Mandatory = $true)]$Verdict, [Parameter(Mandatory = $true)]$Settings)
    $facts = [pscustomobject]@{ HealthStatus = ''; PostureHash = ''; Compliance = ''; PolicyHashClaimed = ''; PolicyHashExpected = ''; PolicyCheck = 'n/a' }
    # Facts are taken only from bodies that passed the body rules ('complete', or rejected
    # afterwards by replay / ordering / clock / policy / routing rules): never from a body that failed
    # validation, so every recorded fact is well-formed and bounded.
    if (-not $Verdict.SignerVerified -or @('complete', 'state', 'policy', 'route') -cnotcontains $Verdict.Stage) { return $facts }
    if (-not ($Verdict.Event -is [System.Collections.IDictionary])) { return $facts }
    $body = $Verdict.Event['body']
    if (-not ($body -is [System.Collections.IDictionary])) { return $facts }
    $text = { param($Name) if ($body.Contains($Name) -and $body[$Name] -is [string]) { return [string]$body[$Name] } return '' }
    switch -CaseSensitive ($Verdict.EventType) {
        'watchtower.heartbeat.v1' { $facts.PolicyHashClaimed = & $text 'policy_hash_claimed' }
        'watchtower.health_report.v1' { $facts.HealthStatus = & $text 'health_status'; $facts.PostureHash = & $text 'posture_hash' }
        'watchtower.policy_attest.v1' {
            $facts.Compliance = & $text 'compliance'
            $facts.PolicyHashClaimed = & $text 'policy_hash_claimed'
            $facts.PostureHash = & $text 'posture_hash'
            $group = & $text 'effective_group'
            $expected = ''
            foreach ($pin in $Settings['policy_pins']) { if ((Test-WtField $pin 'device_id') -and [string]$pin['device_id'] -ceq $Verdict.DeviceId) { $expected = [string]$pin['expected_policy_hash']; break } }
            if (-not $expected) { foreach ($pin in $Settings['policy_pins']) { if ((Test-WtField $pin 'effective_group') -and [string]$pin['effective_group'] -ceq $group) { $expected = [string]$pin['expected_policy_hash']; break } } }
            $facts.PolicyHashExpected = $expected
            if (-not $expected) { $facts.PolicyCheck = 'unpinned' }
            elseif ($expected -ceq $facts.PolicyHashClaimed) { $facts.PolicyCheck = 'match' }
            else { $facts.PolicyCheck = 'mismatch' }
        }
    }
    return $facts
}

function New-WtUnrecordableVerdict {
    # A rejection that carries no packet-supplied data (used when a packet's own fields
    # cannot be recorded). Nothing about the sender is claimed, so nothing is attributed.
    param([Parameter(Mandatory = $true)][string]$Code)
    return [pscustomobject]@{
        Valid = $false; Code = $Code; Detail = 'WT_FAIL:' + $Code; Stage = 'record'; SignerVerified = $false
        PacketId = ''; PacketKind = ''; EventType = ''; EventHash = ''; EventId = ''
        Producer = ''; ProducerInstance = ''; KeyId = ''; Namespace = ''
        DeviceId = ''; ProducerTime = ''; Seq = [long]-1; Event = $null
    }
}

function Limit-WtText {
    # Untrusted strings are capped before they enter evidence. The cut never splits a
    # surrogate pair, and any unpaired surrogate becomes U+FFFD: evidence is strict UTF-8,
    # and one malformed string must never be able to abort a whole ingest run.
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Value, [int]$Max = 256)
    if ($null -eq $Value) { return '' }
    $suffix = ''
    if ($Value.Length -gt $Max) {
        $cut = $Max
        if ($cut -gt 0 -and [char]::IsHighSurrogate($Value[$cut - 1])) { $cut-- }
        $Value = $Value.Substring(0, $cut)
        $suffix = '...[truncated]'
    }
    $builder = $null
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $c = $Value[$i]
        $paired = $false
        if ([char]::IsHighSurrogate($c)) { $paired = ($i + 1 -lt $Value.Length) -and [char]::IsLowSurrogate($Value[$i + 1]) }
        if ([char]::IsSurrogate($c) -and -not $paired -and -not ([char]::IsLowSurrogate($c) -and $i -gt 0 -and [char]::IsHighSurrogate($Value[$i - 1]))) {
            if ($null -eq $builder) { $builder = New-Object System.Text.StringBuilder($Value) }
            $builder[$i] = [char]0xFFFD
        }
    }
    if ($null -ne $builder) { $Value = $builder.ToString() }
    return $Value + $suffix
}

function New-WtReceiptRow {
    # watchtower.telemetry.receipt.v1 (docs/contracts/live-state-surgeon.md). Every field is
    # always present; strings are "" and seq is -1 when unknown.
    param(
        [Parameter(Mandatory = $true)]$Verdict, [Parameter(Mandatory = $true)][bool]$Accepted, [Parameter(Mandatory = $true)]$Facts,
        [Parameter(Mandatory = $true)]$Authority, [Parameter(Mandatory = $true)][string]$VerifiedUtc, [Parameter(Mandatory = $true)][string]$PacketRef,
        [Parameter(Mandatory = $true)][string]$RoutedTo, [string[]]$Roots
    )
    $fail = New-WtObject
    if ($Accepted) { $fail['code'] = 'NONE'; $fail['detail'] = '' }
    else { $fail['code'] = $Verdict.Code; $fail['detail'] = Limit-WtText (Protect-WtDetail -Detail $Verdict.Detail -Roots $Roots) 512 }
    $row = New-WtObject
    $row['schema'] = $script:WtReceiptSchema
    $row['receipt_time'] = $VerifiedUtc
    $row['verifier'] = $Authority.Principal
    $row['verifier_key_id'] = $Authority.KeyId
    $row['node_id'] = $Authority.NodeId
    $row['packet_ref'] = Limit-WtText $PacketRef
    foreach ($pair in @(
            @('packet_id', 'PacketId'), @('packet_kind', 'PacketKind'), @('event_type', 'EventType'), @('event_hash', 'EventHash'), @('event_id', 'EventId'),
            @('producer', 'Producer'), @('producer_instance', 'ProducerInstance'), @('key_id', 'KeyId'), @('namespace', 'Namespace'),
            @('device_id', 'DeviceId'), @('producer_time', 'ProducerTime'))) {
        $row[$pair[0]] = Limit-WtText ([string]$Verdict.($pair[1]))
    }
    $row['seq'] = [long]$Verdict.Seq
    $row['verify_result'] = $(if ($Accepted) { 'ok' } else { 'reject' })
    $row['fail_reason'] = $fail
    $row['stage'] = $Verdict.Stage
    $row['signer_verified'] = [bool]$Verdict.SignerVerified
    $row['health_status'] = $Facts.HealthStatus
    $row['compliance'] = $Facts.Compliance
    $row['policy_hash_claimed'] = $Facts.PolicyHashClaimed
    $row['posture_hash'] = $Facts.PostureHash
    $row['policy_check'] = $Facts.PolicyCheck
    $row['policy_hash_expected'] = $Facts.PolicyHashExpected
    $row['disposition'] = $(if ($Accepted) { 'accepted' } else { 'quarantined' })
    $row['routed_to'] = $RoutedTo
    return , $row
}

function Get-WtFreePath {
    # $Path, or $Path__2, $Path__3 ... whichever does not exist yet.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $Path }
    for ($n = 2; $n -lt 100000; $n++) {
        $candidate = '{0}__{1}' -f $Path, $n
        if (-not (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    throw (New-WtFailure 'NO_FREE_PATH' $Path)
}

function ConvertTo-WtIngestRecord {
    param([Parameter(Mandatory = $true)]$Summary, [Parameter(Mandatory = $true)][string]$VerifiedUtc, [Parameter(Mandatory = $true)]$Authority)
    $record = New-WtObject
    $record['schema'] = $script:WtIngestRunSchema
    $record['run_time'] = $VerifiedUtc
    $record['verifier'] = $Authority.Principal
    $record['node_id'] = $Authority.NodeId
    $record['processed'] = $Summary.Processed
    $record['accepted'] = $Summary.Accepted
    $record['rejected'] = $Summary.Rejected
    $record['ignored'] = @($Summary.Ignored | ForEach-Object { Limit-WtText ([string]$_) })
    $record['receipts_head_hash'] = $Summary.ReceiptHead
    $record['receipt_count'] = $Summary.ReceiptCount
    $record['alerts_head_hash'] = $Summary.AlertHead
    $record['alert_count'] = $Summary.AlertCount
    $record['checkpoint_hash'] = $Summary.CheckpointHash
    $record['outbox_packet_id'] = $Summary.OutboxPacketId
    $record['pledge_hash'] = $Summary.PledgeHash
    if ($Summary.IntegrationWitnessPacketId) { $record['integration_witness_packet_id'] = $Summary.IntegrationWitnessPacketId }
    if ($Summary.IntegrationWitnessError) { $record['integration_witness_error'] = $Summary.IntegrationWitnessError }
    $items = New-Object System.Collections.ArrayList
    foreach ($result in $Summary.Results) {
        $item = New-WtObject
        $item['packet_ref'] = Limit-WtText $result.PacketRef
        $item['verify_result'] = $(if ($result.Accepted) { 'ok' } else { 'reject' })
        $item['code'] = $result.Code
        $item['packet_id'] = $result.PacketId
        $item['routed_to'] = $result.RoutedTo
        $item['receipt_hash'] = $result.ReceiptHash
        [void]$items.Add($item)
    }
    $record['results'] = $items
    return , $record
}
