# Runtime layout and settings.
#
# Everything WatchTower reads or writes at runtime lives under one state root
# (by default the repository root). The layout is fixed and documented in
# docs/canonical/SPEC.md; only behaviour is configurable, through
# <root>/config/watchtower.settings.json (watchtower.settings.v1).

function Get-WtLayout {
    param([Parameter(Mandatory = $true)][string]$Root)
    $base = Resolve-WtFullPath $Root
    if (-not [System.IO.Directory]::Exists($base)) { throw (New-WtFailure 'STATE_ROOT_MISSING' $base) }
    $join = { param([string]$Relative) [System.IO.Path]::Combine($base, $Relative.Replace('/', [string][System.IO.Path]::DirectorySeparatorChar)) }
    return [pscustomobject]@{
        Root              = $base
        Settings          = & $join 'config/watchtower.settings.json'
        AuthorityKey      = & $join 'proofs/keys/watchtower_authority_ed25519'
        TrustBundle       = & $join 'proofs/trust/neverlost/trust_bundle.json'
        AllowedSigners    = & $join 'proofs/trust/neverlost/allowed_signers'
        Inbox             = & $join 'packets/inbox'
        Accepted          = & $join 'packets/receipts'
        Quarantine        = & $join 'packets/quarantine'
        Outbox            = & $join 'packets/outbox'
        ReceiptLedger     = & $join 'proofs/receipts/watchtower.telemetry.receipt.v1.ndjson'
        CheckpointLedger  = & $join 'proofs/receipts/watchtower.checkpoint.v1.ndjson'
        CheckpointSigs    = & $join 'proofs/receipts/checkpoints'
        AlertLedger       = & $join 'proofs/alerts/watchtower.alert.v1.ndjson'
        PledgeLedger      = & $join 'proofs/pledges/watchtower.device_pledge.v1.ndjson'
        PledgeSigs        = & $join 'proofs/pledges/signatures'
        Devices           = & $join 'runtime/devices'
        Services          = & $join 'runtime/services'
        EvidenceIndex     = & $join 'runtime/evidence_index.json'
        LastIngest        = & $join 'runtime/last_ingest.json'
    }
}

function Get-WtDefaultSettings {
    $settings = New-WtObject
    $settings['schema'] = $script:WtSettingsSchema
    $settings['max_future_skew_seconds'] = 300
    $settings['publish'] = [ordered]@{ device_evidence = $true; service_health = $true; nfl_outbox = $true; device_pledge = $true }
    $settings['service_bindings'] = @()
    $settings['policy_pins'] = @()
    return , (Copy-WtJsonValue $settings)
}

function Read-WtSettings {
    # Validated settings; documented defaults when the file is absent.
    param([Parameter(Mandatory = $true)]$Layout)
    if (-not [System.IO.File]::Exists($Layout.Settings)) { return , (Get-WtDefaultSettings) }
    $settings = Read-WtJsonFile -Path $Layout.Settings -Object
    $where = 'settings'
    if ((Get-WtField $settings 'schema' 'string' $where) -cne $script:WtSettingsSchema) { throw (New-WtFailure 'SETTINGS_SCHEMA' $Layout.Settings) }
    # Unknown keys are errors: a misspelt option must never be silently ignored.
    Assert-WtKnownKeys $settings @('schema', 'max_future_skew_seconds', 'publish', 'service_bindings', 'policy_pins') 'settings'
    $defaults = Get-WtDefaultSettings
    foreach ($key in @($defaults.PSBase.Keys)) { if (-not $settings.Contains($key)) { $settings[$key] = $defaults[$key] } }
    $skew = Get-WtField $settings 'max_future_skew_seconds' 'int' $where
    if ($skew -lt 0 -or $skew -gt 86400) { throw (New-WtFailure 'SETTINGS_VALUE' 'max_future_skew_seconds must be 0..86400') }
    $publish = Get-WtField $settings 'publish' 'object' $where
    Assert-WtKnownKeys $publish @('device_evidence', 'service_health', 'nfl_outbox', 'device_pledge') 'settings.publish'
    foreach ($flag in @('device_evidence', 'service_health', 'nfl_outbox', 'device_pledge')) {
        if (-not $publish.Contains($flag)) { $publish[$flag] = $true }
        [void](Get-WtField $publish $flag 'bool' 'settings.publish')
    }
    foreach ($binding in (Get-WtField $settings 'service_bindings' 'array' $where)) {
        Assert-WtKnownKeys $binding @('service_id', 'producer', 'producer_instance', 'device_id') 'settings.service_bindings'
        $serviceId = Get-WtField $binding 'service_id' 'text' 'settings.service_bindings'
        if ($serviceId -cnotmatch $script:WtServiceIdPattern -or $serviceId -match $script:WtReservedNamePattern) {
            throw (New-WtFailure 'SETTINGS_VALUE' ('service_id ' + $serviceId))
        }
        [void](Get-WtField $binding 'producer' 'text' 'settings.service_bindings')
        [void](Get-WtField $binding 'producer_instance' 'text' 'settings.service_bindings')
        if (Test-WtField $binding 'device_id') { [void](Get-WtField $binding 'device_id' 'text' 'settings.service_bindings') }
    }
    foreach ($pin in (Get-WtField $settings 'policy_pins' 'array' $where)) {
        Assert-WtKnownKeys $pin @('device_id', 'effective_group', 'expected_policy_hash') 'settings.policy_pins'
        $hasDevice = Test-WtField $pin 'device_id'
        $hasGroup = Test-WtField $pin 'effective_group'
        if ($hasDevice -eq $hasGroup) { throw (New-WtFailure 'SETTINGS_VALUE' 'policy_pins entries need exactly one of device_id / effective_group') }
        if (-not (Test-WtHex64 ([string](Get-WtField $pin 'expected_policy_hash' 'string' 'settings.policy_pins')))) { throw (New-WtFailure 'SETTINGS_VALUE' 'expected_policy_hash must be 64 lowercase hex') }
    }
    return , $settings
}

function Assert-WtKnownKeys {
    param([Parameter(Mandatory = $true)]$Object, [Parameter(Mandatory = $true)][string[]]$Allowed, [string]$Context)
    if ($Object -isnot [System.Collections.IDictionary]) { throw (New-WtFailure 'FIELD_TYPE' ('{0} expected object' -f $Context)) }
    foreach ($key in $Object.PSBase.Keys) { if ($Allowed -cnotcontains $key) { throw (New-WtFailure 'SETTINGS_UNKNOWN_KEY' ('{0}.{1}' -f $Context, $key)) } }
}

function Get-WtNodeId {
    # Stable identity of this WatchTower node: sha256 of its canonical public key.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$PublicKey)
    return Get-WtSha256 -Text ((ConvertTo-WtPublicKey $PublicKey) + "`n")
}

function Get-WtRootRelative {
    # Root-relative '/' path for records (machine paths never enter evidence).
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)][string]$Path)
    return Get-WtRelativePath -Root $Layout.Root -Path $Path
}

function Protect-WtDetail {
    # Strip machine-specific absolute paths from human-readable failure details.
    [OutputType([string])]
    param([AllowEmptyString()][string]$Detail, [string[]]$Roots)
    $text = [string]$Detail
    foreach ($root in $Roots) {
        if ([string]::IsNullOrEmpty($root)) { continue }
        $full = (Resolve-WtFullPath $root).TrimEnd([char[]]@('\', '/'))
        $text = $text.Replace($full + [System.IO.Path]::DirectorySeparatorChar, '').Replace($full, '.')
    }
    $temp = [System.IO.Path]::GetTempPath().TrimEnd([char[]]@('\', '/'))
    return $text.Replace($temp, '<temp>')
}
