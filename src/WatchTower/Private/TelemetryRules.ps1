# Body rules for inbound telemetry events (live-state-surgeon contract).

function Assert-WtTelemetryBody {
    # Body rules per event type. Fields WatchTower relies on are type-checked and
    # recomputed; informational fields (signals, queue_status, storage_status,
    # last_job, capabilities, evidence_refs, violations) pass through unvalidated.
    param([Parameter(Mandatory = $true)][string]$EventType, [Parameter(Mandatory = $true)]$Body)
    switch -CaseSensitive ($EventType) {
        'watchtower.heartbeat.v1' {
            if ((Get-WtField $Body 'uptime_seconds' 'int' 'body') -lt 0) { throw (New-WtFailure 'BODY_VALUE' 'uptime_seconds < 0') }
            if ((Test-WtField $Body 'policy_hash_claimed') -and -not (Test-WtHex64 ([string]$Body['policy_hash_claimed']))) { throw (New-WtFailure 'BODY_VALUE' 'policy_hash_claimed') }
        }
        'watchtower.health_report.v1' {
            $status = Get-WtField $Body 'health_status' 'string' 'body'
            if (@('ok', 'degraded', 'fail') -cnotcontains $status) { throw (New-WtFailure 'BODY_VALUE' ('health_status=' + $status)) }
            $posture = Get-WtField $Body 'posture' 'object' 'body'
            if ((Get-WtField $posture 'schema' 'string' 'body.posture') -cne 'watchtower.posture.v1') { throw (New-WtFailure 'BODY_VALUE' 'posture.schema') }
            [void](Get-WtField $posture 'measurements' 'any' 'body.posture')
            if ((Get-WtField $Body 'posture_hash' 'string' 'body') -cne (Get-WtCanonicalHash $posture)) { throw (New-WtFailure 'POSTURE_HASH_MISMATCH') }
        }
        'watchtower.policy_attest.v1' {
            [void](Get-WtField $Body 'effective_group' 'text' 'body')
            $policy = Get-WtField $Body 'policy' 'object' 'body'
            if ((Get-WtField $policy 'schema' 'string' 'body.policy') -cne 'covenantgate.effective_policy.v1') { throw (New-WtFailure 'BODY_VALUE' 'policy.schema') }
            $identity = New-WtObject
            foreach ($field in @('schema', 'policy_id', 'policy_version', 'rules_hash')) { $identity[$field] = Get-WtField $policy $field 'text' 'body.policy' }
            if ((Get-WtField $Body 'policy_hash_claimed' 'string' 'body') -cne (Get-WtCanonicalHash $identity)) { throw (New-WtFailure 'POLICY_HASH_MISMATCH') }
            $compliance = Get-WtField $Body 'compliance' 'string' 'body'
            if (@('compliant', 'noncompliant') -cnotcontains $compliance) { throw (New-WtFailure 'BODY_VALUE' ('compliance=' + $compliance)) }
            if ((Test-WtField $Body 'posture_hash') -and -not (Test-WtHex64 ([string]$Body['posture_hash']))) { throw (New-WtFailure 'BODY_VALUE' 'posture_hash') }
        }
        'watchtower.alert.v1' {
            [void](Get-WtField $Body 'alert_type' 'text' 'body')
            $state = Get-WtField $Body 'state' 'string' 'body'
            if (@('unknown', 'stale', 'broken', 'drift', 'degraded', 'ok') -cnotcontains $state) { throw (New-WtFailure 'BODY_VALUE' ('state=' + $state)) }
            foreach ($code in (Get-WtField $Body 'reason_codes' 'array' 'body')) { if (-not ($code -is [string])) { throw (New-WtFailure 'BODY_VALUE' 'reason_codes') } }
        }
        default { throw (New-WtFailure 'EVENT_TYPE_UNSUPPORTED' $EventType) }
    }
}
