# Verified evidence WatchTower publishes for consumers, and alert evidence.
#
# Published documents are projections of the receipt ledger (which stays the
# authority). Each is canonical JSON + LF with a detached signature beside it
# (<file>.sig, namespace 'watchtower'). Freshness always comes from the
# observation time of the verified event, never from publish time, so stale
# telemetry can never look fresh to Constellation.

function New-WtVerificationBlock {
    param([Parameter(Mandatory = $true)]$Verdict, [Parameter(Mandatory = $true)]$Authority, [Parameter(Mandatory = $true)][string]$ReceiptHash, [Parameter(Mandatory = $true)][string]$VerifiedUtc)
    $block = New-WtObject
    $block['verifier'] = $Authority.Principal
    $block['verifier_key_id'] = $Authority.KeyId
    $block['node_id'] = $Authority.NodeId
    $block['receipt_hash'] = $ReceiptHash
    $block['packet_id'] = $Verdict.PacketId
    $block['event_hash'] = $Verdict.EventHash
    $block['producer'] = $Verdict.Producer
    $block['producer_instance'] = $Verdict.ProducerInstance
    $block['verified_utc'] = $VerifiedUtc
    return , $block
}

function Publish-WtSignedDocument {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Document, [Parameter(Mandatory = $true)]$Authority)
    Write-WtJsonFile -Path $Path -Value $Document
    New-WtAuthoritySignature -Authority $Authority -Namespace $script:WtNamespaceEvidence -MessagePath $Path -SignaturePath ($Path + '.sig')
}

function Publish-WtDeviceEvidence {
    # Latest verified heartbeat / health_report / policy_attest per device
    # (watchtower.*.v1 flat documents). Never replaces a newer observation.
    param(
        [Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Verdict, [Parameter(Mandatory = $true)]$Authority,
        [Parameter(Mandatory = $true)][string]$ReceiptHash, [Parameter(Mandatory = $true)][string]$VerifiedUtc, [Parameter(Mandatory = $true)]$Facts
    )
    $body = $Verdict.Event['body']
    $doc = New-WtObject
    $doc['schema'] = $Verdict.EventType
    $doc['device_id'] = $Verdict.DeviceId
    $doc['observed_utc'] = $Verdict.ProducerTime
    $doc['proof_status'] = 'verified'
    switch -CaseSensitive ($Verdict.EventType) {
        'watchtower.heartbeat.v1' {
            $doc['heartbeat_ok'] = $true
            $doc['uptime_seconds'] = $body['uptime_seconds']
            $header = $Verdict.Event['header']
            if ((Test-WtField $header 'software_ref') -and (Test-WtField $header['software_ref'] 'value')) { $doc['agent_version'] = [string]$header['software_ref']['value'] }
        }
        'watchtower.health_report.v1' {
            $doc['health_ok'] = ($Facts.HealthStatus -ceq 'ok')
            $doc['degraded'] = ($Facts.HealthStatus -ceq 'degraded')
            $doc['failure_count'] = $(if ($Facts.HealthStatus -ceq 'fail') { 1 } else { 0 })
            $doc['health_status'] = $Facts.HealthStatus
            $doc['posture_hash'] = $Facts.PostureHash
        }
        'watchtower.policy_attest.v1' {
            $doc['policy_hash'] = $Facts.PolicyHashClaimed
            $doc['policy_ok'] = ($Facts.Compliance -ceq 'compliant' -and $Facts.PolicyCheck -cne 'mismatch')
            $doc['compliance'] = $Facts.Compliance
            $doc['policy_check'] = $Facts.PolicyCheck
            if ($Facts.PolicyHashExpected) { $doc['expected_policy_hash'] = $Facts.PolicyHashExpected }
            if ($Facts.PolicyCheck -ceq 'mismatch') { $doc['drift_reason'] = 'POLICY_HASH_MISMATCH' }
            elseif ($Facts.Compliance -ceq 'noncompliant') { $doc['drift_reason'] = 'COMPLIANCE_NONCOMPLIANT' }
        }
        default { return $null }
    }
    $doc['verification'] = New-WtVerificationBlock -Verdict $Verdict -Authority $Authority -ReceiptHash $ReceiptHash -VerifiedUtc $VerifiedUtc
    $name = $Verdict.EventType.Substring('watchtower.'.Length).Replace('.v1', '') + '.json'
    $path = [System.IO.Path]::Combine($Layout.Devices, (ConvertTo-WtPathSegment $Verdict.DeviceId), $name)
    if ([System.IO.File]::Exists($path)) {
        # Published documents are projections of the receipt ledger. A newer verified
        # observation is never replaced; an unreadable or tampered projection is simply
        # re-published from verified evidence instead of aborting the run.
        $currentObserved = ''
        try { $currentObserved = [string](Read-WtJsonFile -Path $path -Object)['observed_utc'] } catch { $currentObserved = '' }
        if ([string]::CompareOrdinal($currentObserved, $Verdict.ProducerTime) -gt 0) { return $null }
    }
    Publish-WtSignedDocument -Path $path -Document $doc -Authority $Authority
    return $path
}

function Get-WtServiceBinding {
    param([Parameter(Mandatory = $true)]$Settings, [Parameter(Mandatory = $true)]$Verdict)
    foreach ($binding in $Settings['service_bindings']) {
        if ([string]$binding['producer'] -cne $Verdict.Producer) { continue }
        if ([string]$binding['producer_instance'] -cne $Verdict.ProducerInstance) { continue }
        if ((Test-WtField $binding 'device_id') -and [string]$binding['device_id'] -cne $Verdict.DeviceId) { continue }
        return [string]$binding['service_id']
    }
    return ''
}

function Publish-WtServiceHealth {
    # Constellation 'health' facet (registry/evidence_sources.json, proposal 0008):
    # runtime/services/<service_id>/health_report_<observed>_<packet12>.json, schema
    # watchtower.health_report.v1, fields read by oversight.mjs: health_ok, degraded,
    # failure_count, proof_status, observed_utc. Only newer observations are published.
    param(
        [Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)][string]$ServiceId, [Parameter(Mandatory = $true)]$Verdict,
        [Parameter(Mandatory = $true)]$Authority, [Parameter(Mandatory = $true)][string]$ReceiptHash, [Parameter(Mandatory = $true)][string]$VerifiedUtc,
        [Parameter(Mandatory = $true)]$Facts
    )
    $directory = [System.IO.Path]::Combine($Layout.Services, $ServiceId)
    $stamp = (ConvertFrom-WtUtcTime $Verdict.ProducerTime).ToString("yyyyMMdd'T'HHmmss'Z'", $script:WtInvariant)
    if ([System.IO.Directory]::Exists($directory)) {
        foreach ($existing in [System.IO.Directory]::GetFiles($directory, 'health_report_*.json')) {
            $name = [System.IO.Path]::GetFileName($existing)
            if ($name.Length -ge 30 -and [string]::CompareOrdinal($name.Substring(14, 16), $stamp) -ge 0) { return $null }
        }
    }
    $doc = New-WtObject
    $doc['schema'] = 'watchtower.health_report.v1'
    $doc['service_id'] = $ServiceId
    $doc['device_id'] = $Verdict.DeviceId
    $doc['observed_utc'] = $Verdict.ProducerTime
    $doc['health_ok'] = ($Facts.HealthStatus -ceq 'ok')
    $doc['degraded'] = ($Facts.HealthStatus -ceq 'degraded')
    $doc['failure_count'] = $(if ($Facts.HealthStatus -ceq 'fail') { 1 } else { 0 })
    $doc['health_status'] = $Facts.HealthStatus
    $doc['posture_hash'] = $Facts.PostureHash
    $doc['proof_status'] = 'verified'
    $doc['verification'] = New-WtVerificationBlock -Verdict $Verdict -Authority $Authority -ReceiptHash $ReceiptHash -VerifiedUtc $VerifiedUtc
    $path = Join-Path $directory ('health_report_{0}_{1}.json' -f $stamp, $Verdict.PacketId.Substring(0, 12))
    Publish-WtSignedDocument -Path $path -Document $doc -Authority $Authority
    return $path
}

function New-WtAlert {
    param(
        [Parameter(Mandatory = $true)][string]$Type, [Parameter(Mandatory = $true)][ValidateSet('info', 'warning', 'critical')][string]$Severity,
        [Parameter(Mandatory = $true)][ValidateSet('unknown', 'stale', 'broken', 'drift', 'degraded', 'ok')][string]$State,
        [Parameter(Mandatory = $true)][string[]]$ReasonCodes
    )
    return [pscustomobject]@{ Type = $Type; Severity = $Severity; State = $State; ReasonCodes = $ReasonCodes }
}

function Get-WtAlertsFor {
    # Telemetry alert evidence WatchTower owns (registry: "Telemetry alert evidence").
    param([Parameter(Mandatory = $true)]$Verdict, [Parameter(Mandatory = $true)][bool]$Accepted, [Parameter(Mandatory = $true)]$Facts)
    $alerts = New-Object System.Collections.ArrayList
    if (-not $Accepted) {
        if ($Verdict.SignerVerified) {
            $severity = 'warning'
            if (@('DUPLICATE_PACKET', 'REPLAYED_EVENT', 'SEQUENCE_REPLAYED', 'SEQUENCE_REGRESSION', 'TIME_REGRESSION', 'FUTURE_TIMESTAMP') -ccontains $Verdict.Code) { $severity = 'critical' }
            [void]$alerts.Add((New-WtAlert -Type 'TELEMETRY_REJECTED' -Severity $severity -State 'unknown' -ReasonCodes @($Verdict.Code)))
        }
        else {
            [void]$alerts.Add((New-WtAlert -Type 'UNVERIFIED_PACKET' -Severity 'warning' -State 'unknown' -ReasonCodes @($Verdict.Code)))
        }
        return , $alerts
    }
    switch -CaseSensitive ($Verdict.EventType) {
        'watchtower.health_report.v1' {
            if ($Facts.HealthStatus -ceq 'fail') { [void]$alerts.Add((New-WtAlert -Type 'HEALTH_FAIL' -Severity 'critical' -State 'broken' -ReasonCodes @('HEALTH_STATUS_FAIL'))) }
            elseif ($Facts.HealthStatus -ceq 'degraded') { [void]$alerts.Add((New-WtAlert -Type 'HEALTH_DEGRADED' -Severity 'warning' -State 'degraded' -ReasonCodes @('HEALTH_STATUS_DEGRADED'))) }
        }
        'watchtower.policy_attest.v1' {
            if ($Facts.PolicyCheck -ceq 'mismatch') { [void]$alerts.Add((New-WtAlert -Type 'POLICY_DRIFT' -Severity 'critical' -State 'drift' -ReasonCodes @('POLICY_HASH_MISMATCH'))) }
            if ($Facts.Compliance -ceq 'noncompliant') { [void]$alerts.Add((New-WtAlert -Type 'POLICY_NONCOMPLIANT' -Severity 'warning' -State 'drift' -ReasonCodes @('COMPLIANCE_NONCOMPLIANT'))) }
        }
        'watchtower.alert.v1' {
            $body = $Verdict.Event['body']
            $state = [string]$body['state']
            $severity = 'info'
            if ($state -ceq 'broken') { $severity = 'critical' } elseif (@('drift', 'stale', 'degraded') -ccontains $state) { $severity = 'warning' }
            $codes = [string[]]@($body['reason_codes'] | ForEach-Object { [string]$_ })
            if ($codes.Length -eq 0) { $codes = @('PRODUCER_ALERT') }
            [void]$alerts.Add((New-WtAlert -Type ('PRODUCER_' + [string]$body['alert_type']) -Severity $severity -State $state -ReasonCodes $codes))
        }
    }
    return , $alerts
}

function Add-WtAlertRecord {
    param(
        [Parameter(Mandatory = $true)]$Chain, [Parameter(Mandatory = $true)]$Alert, [Parameter(Mandatory = $true)]$Verdict,
        [Parameter(Mandatory = $true)]$Authority, [Parameter(Mandatory = $true)][string]$ReceiptHash, [Parameter(Mandatory = $true)][string]$VerifiedUtc
    )
    $row = New-WtObject
    $row['schema'] = $script:WtAlertSchema
    $row['alert_time'] = $VerifiedUtc
    $row['observed_utc'] = $(if ($Verdict.ProducerTime -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { $Verdict.ProducerTime } else { $VerifiedUtc })
    # Never attribute an alert to a device named only by an unverified (attacker-writable) header.
    $row['device_id'] = $(if ($Verdict.SignerVerified -and $Verdict.DeviceId -cmatch $script:WtIdentifierPattern) { $Verdict.DeviceId } else { 'unknown' })
    $row['alert_type'] = $Alert.Type
    $row['severity'] = $Alert.Severity
    $row['state'] = $Alert.State
    $row['reason'] = $Alert.ReasonCodes[0]
    $row['reason_codes'] = $Alert.ReasonCodes
    $evidence = New-Object System.Collections.ArrayList
    foreach ($pair in @(@('packet_id', $Verdict.PacketId), @('event_hash', $Verdict.EventHash), @('watchtower_receipt_hash', $ReceiptHash))) {
        if ($pair[1]) { $item = New-WtObject; $item['kind'] = $pair[0]; $item['value'] = $pair[1]; [void]$evidence.Add($item) }
    }
    $row['evidence'] = $evidence
    $row['verifier'] = $Authority.Principal
    $row['verifier_key_id'] = $Authority.KeyId
    $row['prev_alert_hash'] = $Chain.Head
    $row['alert_id'] = Get-WtCanonicalHash $row
    return Add-WtHashChainEntry -Chain $Chain -Row $row
}
