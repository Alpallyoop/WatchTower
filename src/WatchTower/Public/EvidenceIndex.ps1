function Export-WtEvidenceIndex {
    <#
    .SYNOPSIS
        Writes runtime/evidence_index.json (watchtower.evidence_index.v1).
    .DESCRIPTION
        A discovery document for operator surfaces such as the Global Workbench WatchTower plugin
        (alert, device and receipt panels): where each ledger lives with its verified count and
        head, the latest verified documents per device and service, recent outbox packets and the
        last ingest record. It never throws on a damaged ledger; the ledger entry carries
        state 'invalid' and the failure code instead, so a broken chain is never shown as healthy.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Root, [string]$GeneratedUtc = (Get-WtUtcNow))
    [void](ConvertFrom-WtUtcTime $GeneratedUtc 'GeneratedUtc')
    $layout = Get-WtLayout $Root
    $index = New-WtObject
    $index['schema'] = $script:WtEvidenceIndexSchema
    $index['generated_utc'] = $GeneratedUtc
    $index['settings_schema'] = $script:WtSettingsSchema

    $verifier = New-WtObject
    $verifier['principal'] = $script:WtAuthorityPrincipal
    $verifier['key_id'] = $script:WtAuthorityKeyId
    $verifier['node_id'] = ''
    if ([System.IO.File]::Exists($layout.AuthorityKey + '.pub')) { try { $verifier['node_id'] = Get-WtNodeId (Read-WtText ($layout.AuthorityKey + '.pub')) } catch { $verifier['node_id'] = '' } }
    $index['verifier'] = $verifier

    $ledgers = New-WtObject
    foreach ($spec in @(
            @('telemetry_receipts', $layout.ReceiptLedger, 'receipt_hash', 'prev_receipt_hash'),
            @('alerts', $layout.AlertLedger, 'alert_hash', 'prev_alert_hash'),
            @('checkpoints', $layout.CheckpointLedger, 'checkpoint_hash', 'prev_checkpoint_hash'),
            @('pledges', $layout.PledgeLedger, 'pledge_hash', 'prev_pledge_hash'))) {
        $entry = New-WtObject
        $entry['path'] = Get-WtRootRelative $layout $spec[1]
        try {
            $chain = Open-WtHashChain -Path $spec[1] -HashField $spec[2] -PrevField $spec[3]
            $entry['state'] = 'verified'; $entry['count'] = $chain.Count; $entry['head'] = $chain.Head
        }
        catch { $entry['state'] = 'invalid'; $entry['code'] = Get-WtFailureCode $_; $entry['count'] = 0; $entry['head'] = '' }
        $ledgers[$spec[0]] = $entry
    }
    $index['ledgers'] = $ledgers

    $devices = New-Object System.Collections.ArrayList
    if ([System.IO.Directory]::Exists($layout.Devices)) {
        $ids = [string[]]@([System.IO.Directory]::GetDirectories($layout.Devices) | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        [Array]::Sort($ids, [System.StringComparer]::Ordinal)
        foreach ($folder in $ids) {
            # The folder is a path-safe form of the device id (ConvertTo-WtPathSegment);
            # the id itself is read back from the verified documents inside it.
            $documents = New-WtObject
            $deviceId = ''
            foreach ($kind in @('heartbeat', 'health_report', 'policy_attest')) {
                $path = [System.IO.Path]::Combine($layout.Devices, $folder, $kind + '.json')
                if (-not [System.IO.File]::Exists($path)) { continue }
                $documents[$kind] = Get-WtRootRelative $layout $path
                if (-not $deviceId) { try { $deviceId = [string](Read-WtJsonFile -Path $path -Object)['device_id'] } catch { $deviceId = '' } }
            }
            $device = New-WtObject
            $device['device_id'] = $deviceId
            $device['folder'] = 'runtime/devices/' + $folder
            $device['documents'] = $documents
            [void]$devices.Add($device)
        }
    }
    $index['devices'] = $devices

    $services = New-Object System.Collections.ArrayList
    if ([System.IO.Directory]::Exists($layout.Services)) {
        $ids = [string[]]@([System.IO.Directory]::GetDirectories($layout.Services) | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        [Array]::Sort($ids, [System.StringComparer]::Ordinal)
        foreach ($id in $ids) {
            $reports = [string[]]@([System.IO.Directory]::GetFiles([System.IO.Path]::Combine($layout.Services, $id), 'health_report_*.json') | ForEach-Object { [System.IO.Path]::GetFileName($_) })
            if ($reports.Length -eq 0) { continue }
            [Array]::Sort($reports, [System.StringComparer]::Ordinal)
            $service = New-WtObject
            $service['service_id'] = $id
            $service['latest_health_report'] = 'runtime/services/{0}/{1}' -f $id, $reports[$reports.Length - 1]
            $service['report_count'] = $reports.Length
            [void]$services.Add($service)
        }
    }
    $index['services'] = $services

    $outbox = New-WtObject
    $packets = @()
    if ([System.IO.Directory]::Exists($layout.Outbox)) { $packets = [string[]]@([System.IO.Directory]::GetDirectories($layout.Outbox) | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Where-Object { Test-WtHex64 $_ }) }
    $outbox['path'] = Get-WtRootRelative $layout $layout.Outbox
    $outbox['packet_count'] = @($packets).Count
    $index['outbox'] = $outbox
    $index['last_ingest'] = $(if ([System.IO.File]::Exists($layout.LastIngest)) { Get-WtRootRelative $layout $layout.LastIngest } else { '' })

    Write-WtJsonFile -Path $layout.EvidenceIndex -Value $index
    return $layout.EvidenceIndex
}
