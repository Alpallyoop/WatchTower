function Invoke-WtDoctor {
    <#
    .SYNOPSIS
        Self-check of this WatchTower node; optionally publishes its own health report.
    .DESCRIPTION
        Checks settings, the trust bundle and derived allowed_signers, the authority key, all
        ledgers (Test-WtLedger, including integration receipts), the policy gate when one is
        configured (Arbiter found, policy readable), a stale ingest lock and the inbox backlog. With -Publish it
        writes runtime/doctor_report.json and a signed watchtower.health_report.v1 for the
        'watchtower' service under runtime/services/watchtower/, which is what Constellation's
        health facet reads for WatchTower itself ("WatchTower status ... doctor result").
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$VerificationTime = (Get-WtUtcNow),
        [switch]$Publish
    )
    [void](ConvertFrom-WtUtcTime $VerificationTime 'VerificationTime')
    $layout = Get-WtLayout $Root
    # Each check runs in isolation and may record what it learned in $context.
    $context = @{ Bundle = $null; Authority = $null }
    $checks = New-Object System.Collections.ArrayList
    $run = {
        param([string]$Name, [scriptblock]$Check)
        $item = New-WtObject
        $item['name'] = $Name
        try { $note = & $Check; $item['ok'] = $true; $item['code'] = 'OK'; $item['detail'] = [string]$note }
        catch { $item['ok'] = $false; $item['code'] = Get-WtFailureCode $_; $item['detail'] = Limit-WtText (Protect-WtDetail -Detail (Get-WtFailureMessage $_) -Roots @($layout.Root)) 512 }
        [void]$checks.Add($item)
    }
    & $run 'ssh_keygen' { 'SSHSIG sign/verify works: ' + [System.IO.Path]::GetFileName((Test-WtSshSigSupport)) }
    & $run 'settings' { [void](Read-WtSettings $layout); 'valid' }
    & $run 'trust_bundle' { $context.Bundle = Read-WtTrustBundle $layout.TrustBundle -Root $layout.Root; 'valid' }
    & $run 'allowed_signers_derived' {
        if ($null -eq $context.Bundle) { throw (New-WtFailure 'TRUST_BUNDLE_UNAVAILABLE') }
        if (-not [System.IO.File]::Exists($layout.AllowedSigners) -or (Read-WtText $layout.AllowedSigners) -cne (ConvertTo-WtAllowedSigners $context.Bundle)) { throw (New-WtFailure 'ALLOWED_SIGNERS_NOT_DERIVED') }
        'matches trust bundle'
    }
    & $run 'authority_key' {
        if ($null -eq $context.Bundle) { throw (New-WtFailure 'TRUST_BUNDLE_UNAVAILABLE') }
        $context.Authority = Get-WtAuthority -Layout $layout -Bundle $context.Bundle
        'node ' + $context.Authority.NodeId
    }
    & $run 'ledgers' {
        $ledger = Test-WtLedger -Root $layout.Root
        if (-not $ledger.Valid) { throw (New-WtFailure $ledger.Code $ledger.Detail) }
        $integrationCount = [long](@($ledger.Ledgers.Integrations | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum
        'receipts={0} alerts={1} checkpoints={2} pledges={3} integration_receipts={4} warnings={5}' -f $ledger.Ledgers.Receipts.Count, $ledger.Ledgers.Alerts.Count, $ledger.Ledgers.Checkpoints.Count, $ledger.Ledgers.Pledges.Count, $integrationCount, $ledger.Warnings.Count
    }
    & $run 'policy_gate' {
        $settings = Read-WtSettings $layout
        $gate = Read-WtPolicyGate -Layout $layout -Settings $settings -ReadOnly
        if ($null -eq $gate) { 'off (no settings.arbiter)' }
        else {
            if ($gate.Error) { throw (New-WtFailure 'POLICY_SET_INVALID' $gate.Error) }
            if (-not $gate.Engine) { throw (New-WtFailure 'POLICY_EVALUATOR_UNAVAILABLE' 'set WATCHTOWER_ARBITER_ROOT or place an arbiter checkout beside this repository') }
            'arbiter ready, policy ' + $gate.PolicyHash
        }
    }
    & $run 'ingest_lock' {
        if ([System.IO.File]::Exists([System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($layout.LastIngest), 'ingest.lock'))) { throw (New-WtFailure 'INGEST_LOCK_PRESENT' 'runtime/ingest.lock') }
        'clear'
    }
    $authority = $context.Authority
    $pending = 0
    if ([System.IO.Directory]::Exists($layout.Inbox)) { $pending = @([System.IO.Directory]::GetDirectories($layout.Inbox) | Where-Object { $name = [System.IO.Path]::GetFileName($_); -not ($name.StartsWith('.') -or $name.StartsWith('_')) }).Count }

    $failed = @($checks | Where-Object { -not $_['ok'] }).Count
    $report = New-WtObject
    $report['schema'] = $script:WtDoctorSchema
    $report['observed_utc'] = $VerificationTime
    $report['health_ok'] = ($failed -eq 0)
    $report['failure_count'] = $failed
    $report['inbox_pending'] = $pending
    $report['checks'] = $checks
    $report['node_id'] = $(if ($authority) { $authority.NodeId } else { '' })

    if ($Publish) {
        Write-WtJsonFile -Path ([System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($layout.LastIngest), 'doctor_report.json')) -Value $report
        if ($null -eq $authority) { throw (New-WtFailure 'DOCTOR_CANNOT_SIGN' 'authority unavailable; report written unsigned to runtime/doctor_report.json') }
        $health = New-WtObject
        $health['schema'] = 'watchtower.health_report.v1'
        $health['service_id'] = 'watchtower'
        $health['device_id'] = $authority.NodeId
        $health['observed_utc'] = $VerificationTime
        $health['health_ok'] = ($failed -eq 0)
        $health['degraded'] = $false
        $health['failure_count'] = $failed
        $health['health_status'] = $(if ($failed -eq 0) { 'ok' } else { 'fail' })
        $health['proof_status'] = 'self-check'
        $health['checks'] = $checks
        $verification = New-WtObject
        $verification['verifier'] = $authority.Principal
        $verification['verifier_key_id'] = $authority.KeyId
        $verification['node_id'] = $authority.NodeId
        $verification['verified_utc'] = $VerificationTime
        $health['verification'] = $verification
        $stamp = (ConvertFrom-WtUtcTime $VerificationTime).ToString("yyyyMMdd'T'HHmmss'Z'", $script:WtInvariant)
        $path = [System.IO.Path]::Combine($layout.Services, 'watchtower', ('health_report_{0}_doctor.json' -f $stamp))
        Publish-WtSignedDocument -Path $path -Document $health -Authority $authority
        [void](Export-WtEvidenceIndex -Root $layout.Root -GeneratedUtc $VerificationTime)
    }
    return [pscustomobject]@{ HealthOk = ($failed -eq 0); FailureCount = $failed; InboxPending = $pending; Checks = $checks; Report = $report }
}
