function Initialize-WtTrust {
    <#
    .SYNOPSIS
        Creates (or validates) this node's authority key and NeverLost trust bundle.
    .DESCRIPTION
        - Authority key: proofs/keys/watchtower_authority_ed25519 (created if absent, never
          overwritten). Principal and key id are the ones NeverLost registers for WatchTower.
        - Trust bundle: proofs/trust/neverlost/trust_bundle.json (neverlost.trust_bundle.v1),
          the single source of truth; allowed_signers beside it is derived only.
        - Enrolled producers already in the bundle are preserved.
        - If the bundle names a different authority key than the one on disk, this fails
          (TRUST_AUTHORITY_KEY_MISMATCH): key rotation is an explicit operator decision.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$CreatedUtc = (Get-WtUtcNow)
    )
    [void](ConvertFrom-WtUtcTime $CreatedUtc 'CreatedUtc')
    $layout = Get-WtLayout $Root
    $createdKey = $false
    if (-not [System.IO.File]::Exists($layout.AuthorityKey)) {
        if ([System.IO.File]::Exists($layout.AuthorityKey + '.pub')) { throw (New-WtFailure 'AUTHORITY_KEY_INCOMPLETE' 'public key without private key') }
        New-WtSshKey -Path $layout.AuthorityKey -Comment 'watchtower-authority'
        $createdKey = $true
    }
    $publicKeyFile = $layout.AuthorityKey + '.pub'
    $publicKey = ConvertTo-WtPublicKey (Read-WtText $publicKeyFile)

    $publicKeyPath = Get-WtRootRelative $layout $publicKeyFile
    if ([System.IO.File]::Exists($layout.TrustBundle)) {
        # Authority first, so a replaced key is reported as the rotation it is; then every key file.
        $bundle = Read-WtTrustBundle $layout.TrustBundle
        $authority = Find-WtTrustKey -Bundle $bundle -Principal $script:WtAuthorityPrincipal -KeyId $script:WtAuthorityKeyId
        if ($null -eq $authority) { throw (New-WtFailure 'TRUST_AUTHORITY_MISSING' $layout.TrustBundle) }
        if ([string]$authority['pubkey'] -cne $publicKey) { throw (New-WtFailure 'TRUST_AUTHORITY_KEY_MISMATCH' 'bundle and proofs/keys disagree; rotate explicitly') }
        Assert-WtTrustKeyMaterial -Bundle $bundle -Root $layout.Root
        if (-not (Test-WtField $authority 'pubkey_path')) {
            # Bundles written before 2.1.0 lack pubkey_path, which NeverLost v1 requires. Adding it
            # changes no key, namespace or allowed_signers line; the file it names is re-verified.
            $authority['pubkey_path'] = $publicKeyPath
            $authority['pubkey_sha256'] = Get-WtSha256 -Path $publicKeyFile
            $bundle = Copy-WtJsonValue $bundle
            Assert-WtTrustBundle $bundle
            Assert-WtTrustKeyMaterial -Bundle $bundle -Root $layout.Root
            Write-WtJsonFile -Path $layout.TrustBundle -Value $bundle
        }
    }
    else {
        $key = New-WtObject
        $key['key_id'] = $script:WtAuthorityKeyId
        $key['alg'] = 'ssh-ed25519'
        $key['pubkey'] = $publicKey
        $key['pubkey_path'] = $publicKeyPath
        $key['pubkey_sha256'] = Get-WtSha256 -Path $publicKeyFile
        $key['namespaces'] = $script:WtAuthorityNamespaces
        $principal = New-WtObject
        $principal['principal'] = $script:WtAuthorityPrincipal
        $principal['keys'] = @($key)
        $bundle = New-WtObject
        $bundle['schema'] = 'neverlost.trust_bundle.v1'
        $bundle['created_utc'] = $CreatedUtc
        $bundle['principals'] = @($principal)
        $bundle = Copy-WtJsonValue $bundle
        Assert-WtTrustBundle $bundle
        Write-WtJsonFile -Path $layout.TrustBundle -Value $bundle
    }
    Write-WtText -Path $layout.AllowedSigners -Text (ConvertTo-WtAllowedSigners $bundle)

    return [pscustomobject]@{
        Principal      = $script:WtAuthorityPrincipal
        KeyId          = $script:WtAuthorityKeyId
        NodeId         = Get-WtNodeId $publicKey
        PublicKey      = $publicKey
        CreatedKey     = $createdKey
        TrustBundle    = $layout.TrustBundle
        AllowedSigners = $layout.AllowedSigners
    }
}

function Register-WtProducer {
    <#
    .SYNOPSIS
        Enrolls a telemetry producer (for example live-state-surgeon) in the trust bundle.
    .DESCRIPTION
        Adds principal + key + namespaces. Idempotent for an identical entry; fails if the
        principal/key id is already enrolled with a different key or different namespaces
        (TRUST_PRODUCER_CONFLICT). Keys whose comment marks them as test material
        (TEST_ONLY) are refused unless -AllowTestKey is given. -Namespace defaults to every
        producer namespace and may only narrow it (TRUST_NAMESPACE_NOT_PRODUCER otherwise).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Principal,
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$PublicKey,
        [string[]]$Namespace = $script:WtProducerNamespaces,
        [switch]$AllowTestKey
    )
    $layout = Get-WtLayout $Root
    $bundle = Read-WtTrustBundle $layout.TrustBundle -Root $layout.Root
    if ($Principal -ceq $script:WtAuthorityPrincipal) { throw (New-WtFailure 'TRUST_PRODUCER_IS_AUTHORITY') }
    $line = $PublicKey
    if ([System.IO.File]::Exists($PublicKey)) { $line = Read-WtText $PublicKey }
    if (-not $AllowTestKey -and $line -match 'TEST_ONLY') { throw (New-WtFailure 'TRUST_TEST_KEY_REFUSED' $KeyId) }
    $canonicalKey = ConvertTo-WtPublicKey $line
    $namespaces = [string[]]@($Namespace)
    # A producer may hold only producer namespaces: never WatchTower's own evidence, pledge or
    # envelope namespaces, and never an empty set.
    if ($namespaces.Length -eq 0) { throw (New-WtFailure 'TRUST_KEY_NO_NAMESPACES' $KeyId) }
    foreach ($ns in $namespaces) { if ($script:WtProducerNamespaces -cnotcontains $ns) { throw (New-WtFailure 'TRUST_NAMESPACE_NOT_PRODUCER' $ns) } }
    [Array]::Sort($namespaces, [System.StringComparer]::Ordinal)

    $existing = Find-WtTrustKey -Bundle $bundle -Principal $Principal -KeyId $KeyId
    if ($null -ne $existing) {
        $existingNamespaces = [string[]]@($existing['namespaces'] | ForEach-Object { [string]$_ })
        [Array]::Sort($existingNamespaces, [System.StringComparer]::Ordinal)
        if ([string]$existing['pubkey'] -cne $canonicalKey -or ($existingNamespaces -join ',') -cne ($namespaces -join ',')) {
            throw (New-WtFailure 'TRUST_PRODUCER_CONFLICT' ('{0}/{1}' -f $Principal, $KeyId))
        }
        return [pscustomobject]@{ Principal = $Principal; KeyId = $KeyId; Changed = $false }
    }

    foreach ($entry in $bundle['principals']) {
        foreach ($other in $entry['keys']) {
            if ([string]::Equals([string]$other['key_id'], $KeyId, [StringComparison]::OrdinalIgnoreCase)) { throw (New-WtFailure 'TRUST_DUPLICATE_KEY_ID' ('{0} is already enrolled for {1}' -f $KeyId, $entry['principal'])) }
        }
    }
    # The key file NeverLost v1 requires beside every bundle entry (pubkey_path + pubkey_sha256),
    # kept inside the state root: proofs/trust/neverlost/keys/<key id>.pub.
    $keyFile = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($layout.TrustBundle), 'keys', (ConvertTo-WtPathSegment $KeyId) + '.pub')
    $keyBytes = ConvertTo-WtUtf8 ($canonicalKey + "`n")
    if ([System.IO.File]::Exists($keyFile) -and (Get-WtSha256 -Path $keyFile) -cne (Get-WtSha256 -Bytes $keyBytes)) { throw (New-WtFailure 'TRUST_KEY_FILE_CONFLICT' (Get-WtRootRelative $layout $keyFile)) }
    $key = New-WtObject
    $key['key_id'] = $KeyId
    $key['alg'] = 'ssh-ed25519'
    $key['pubkey'] = $canonicalKey
    $key['pubkey_path'] = Get-WtRootRelative $layout $keyFile
    $key['pubkey_sha256'] = Get-WtSha256 -Bytes $keyBytes
    $key['namespaces'] = $namespaces
    $target = $null
    foreach ($entry in $bundle['principals']) { if ([string]$entry['principal'] -ceq $Principal) { $target = $entry } }
    if ($null -eq $target) {
        $target = New-WtObject
        $target['principal'] = $Principal
        $target['keys'] = New-Object System.Collections.ArrayList
        [void]$bundle['principals'].Add($target)
    }
    [void]$target['keys'].Add($key)
    # Validate the whole candidate bundle before anything is written, so a refused enrolment
    # leaves no key file behind.
    $bundle = Copy-WtJsonValue $bundle
    Assert-WtTrustBundle $bundle
    if (-not [System.IO.File]::Exists($keyFile)) { Write-WtBytes -Path $keyFile -Bytes $keyBytes }
    Assert-WtTrustKeyMaterial -Bundle $bundle -Root $layout.Root
    Write-WtJsonFile -Path $layout.TrustBundle -Value $bundle
    Write-WtText -Path $layout.AllowedSigners -Text (ConvertTo-WtAllowedSigners $bundle)
    return [pscustomobject]@{ Principal = $Principal; KeyId = $KeyId; Changed = $true }
}

function Get-WtTrust {
    <#
    .SYNOPSIS
        Loads and validates the trust bundle and confirms allowed_signers is exactly derived.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$Root)
    $layout = Get-WtLayout $Root
    $bundle = Read-WtTrustBundle $layout.TrustBundle -Root $layout.Root
    $expected = ConvertTo-WtAllowedSigners $bundle
    $derivedOk = [System.IO.File]::Exists($layout.AllowedSigners) -and ((Read-WtText $layout.AllowedSigners) -ceq $expected)
    $principals = @(foreach ($entry in $bundle['principals']) {
            foreach ($key in $entry['keys']) {
                [pscustomobject]@{ Principal = [string]$entry['principal']; KeyId = [string]$key['key_id']; Namespaces = @($key['namespaces']) }
            }
        })
    return [pscustomobject]@{
        Bundle                = $bundle
        Principals            = $principals
        AllowedSignersDerived = $derivedOk
        TrustBundle           = $layout.TrustBundle
    }
}

function Import-WtNeverLostProducer {
    <#
    .SYNOPSIS
        Enrolls a producer from a NeverLost-issued trust bundle (registry integration
        watchtower > neverlost, contract neverlost.trust_bundle.v1, carries neverlost.receipt.v1).
    .DESCRIPTION
        Reads a NeverLost v1 trust bundle (NeverLost's bundles are per product; this one is the
        bundle NeverLost issued for WatchTower's producers), verifies it as NeverLost does
        (strict JSON, schema, pubkey_path + pubkey_sha256 recomputed against -BundleRoot, unique
        key ids), and enrolls the keys of -Principal through Register-WtProducer. Only
        device_agent principals can be producers. The bundle's namespaces for a key must all be
        producer namespaces, unless -Namespace narrows them to a subset it grants.
        -NeverLostReceipt: a file holding the one neverlost.receipt.v1 line that authorised the
        bundle; when it names trust_bundle_sha256 that must be the bundle's hash. Its SHA-256 is
        carried in the integration receipt.
        Every call writes one constellation.integration.receipt.v1 (watchtower > neverlost),
        including failed ones.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$BundlePath,
        [Parameter(Mandatory = $true)][string]$Principal,
        [string]$BundleRoot = '',
        [string]$KeyId = '',
        [string[]]$Namespace = @(),
        [string]$NeverLostReceipt = '',
        [switch]$AllowTestKey
    )
    $layout = Get-WtLayout $Root
    $responseSha = ''
    $carried = @()
    $snapshot = $null
    $keysDirectory = ''
    $enrolled = New-Object System.Collections.ArrayList
    $record = {
        param([string]$Outcome, [string]$Token)
        $receipt = New-WtIntegrationReceipt -Provider 'neverlost' -Contract 'neverlost.trust_bundle.v1' -RequestSha256 '' -ResponseSha256 $responseSha `
            -Outcome $Outcome -ErrorToken $Token -Carried $carried
        return (Add-WtIntegrationReceipt -Layout $layout -Receipt $receipt)
    }
    if (-not [System.IO.File]::Exists($BundlePath)) {
        [void](& $record 'unavailable' 'TRUST_SOURCE_MISSING')
        throw (New-WtFailure 'TRUST_SOURCE_MISSING' $BundlePath)
    }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($BundlePath)
        $responseSha = Get-WtSha256 -Bytes $bytes
        if (-not $BundleRoot) {
            # NeverLost layout: <neverlost root>/proofs/trust/trust_bundle.json
            $BundleRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($BundlePath)), '..', '..'))
        }
        if ($NeverLostReceipt) {
            $receiptText = Read-WtText $NeverLostReceipt
            if ($receiptText.EndsWith("`n")) { $receiptText = $receiptText.Substring(0, $receiptText.Length - 1) }
            if ($receiptText.Length -eq 0 -or $receiptText.Contains("`n") -or $receiptText.Contains("`r")) { throw (New-WtFailure 'TRUST_RECEIPT_FORMAT' 'one neverlost.receipt.v1 line expected') }
            $line = ConvertFrom-WtJson $receiptText
            if ($line -isnot [System.Collections.IDictionary]) { throw (New-WtFailure 'TRUST_RECEIPT_FORMAT' 'not an object') }
            $family = $(if ($line['schema'] -is [string]) { [string]$line['schema'] } elseif ($line['event_type'] -is [string]) { [string]$line['event_type'] } else { '' })
            if ($family -cnotmatch '^neverlost[./]') { throw (New-WtFailure 'TRUST_RECEIPT_FORMAT' 'not a neverlost receipt') }
            if ($line.Contains('trust_bundle_sha256') -and [string]$line['trust_bundle_sha256'] -cne $responseSha) { throw (New-WtFailure 'TRUST_RECEIPT_MISMATCH' 'receipt names a different trust bundle') }
            $carried = @([pscustomobject]@{ Contract = 'neverlost.receipt.v1'; Sha256 = (Get-WtSha256 -Text $receiptText) })
        }
        $bundle = ConvertFrom-WtJson (ConvertFrom-WtUtf8 -Bytes $bytes -Source $BundlePath)
        # NeverLost allows namespaces on the principal as well as on each key; a key's grant is the
        # union. Fold principal-level grants into the keys before WatchTower's own rules apply.
        if ($bundle -is [System.Collections.IDictionary] -and $bundle['principals'] -is [System.Collections.IList]) {
            foreach ($entry in $bundle['principals']) {
                if ($entry -isnot [System.Collections.IDictionary] -or -not $entry.Contains('namespaces')) { continue }
                foreach ($key in @($entry['keys'])) {
                    if ($key -isnot [System.Collections.IDictionary]) { continue }
                    $union = New-Object System.Collections.ArrayList
                    if ($key.Contains('namespaces')) { foreach ($ns in $key['namespaces']) { if ($union -cnotcontains $ns) { [void]$union.Add($ns) } } }
                    foreach ($ns in $entry['namespaces']) { if ($union -cnotcontains $ns) { [void]$union.Add($ns) } }
                    $key['namespaces'] = $union
                }
                $entry.Remove('namespaces')
            }
        }
        Assert-WtTrustBundle -Bundle $bundle -Source 'neverlost bundle'
        foreach ($field in $bundle.PSBase.Keys) { if (@('schema', 'created_utc', 'principals') -cnotcontains [string]$field) { throw (New-WtFailure 'TRUST_SOURCE_UNKNOWN_FIELD' ([string]$field)) } }
        foreach ($entry in $bundle['principals']) {
            foreach ($key in $entry['keys']) {
                if (-not (Test-WtField $key 'pubkey_path')) { throw (New-WtFailure 'TRUST_SOURCE_NOT_NEVERLOST_V1' ('{0} has no pubkey_path' -f $key['key_id'])) }
            }
        }
        Assert-WtTrustKeyMaterial -Bundle $bundle -Root $BundleRoot
        if ($Principal -cnotmatch '^single-tenant/device_agent/[^\s,"]+$') { throw (New-WtFailure 'TRUST_SOURCE_ROLE' ('only device_agent principals can be producers: ' + $Principal)) }
        $source = $null
        foreach ($entry in $bundle['principals']) { if ([string]$entry['principal'] -ceq $Principal) { $source = $entry } }
        if ($null -eq $source) { throw (New-WtFailure 'TRUST_SOURCE_PRINCIPAL_ABSENT' $Principal) }
        $keys = @($source['keys'] | Where-Object { -not $KeyId -or [string]$_['key_id'] -ceq $KeyId })
        if ($keys.Count -eq 0) { throw (New-WtFailure 'TRUST_SOURCE_KEY_ABSENT' $KeyId) }
        $keysDirectory = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($layout.TrustBundle), 'keys')
        $snapshot = [pscustomobject]@{
            Bundle = [System.IO.File]::ReadAllBytes($layout.TrustBundle); Signers = [System.IO.File]::ReadAllBytes($layout.AllowedSigners)
            Keys = [string[]]@(Get-ChildItem -LiteralPath $keysDirectory -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        }
        foreach ($key in $keys) {
            $granted = [string[]]@($key['namespaces'] | ForEach-Object { [string]$_ })
            if ($Namespace.Count -gt 0) {
                foreach ($ns in $Namespace) { if ($granted -cnotcontains $ns) { throw (New-WtFailure 'TRUST_NAMESPACE_NOT_GRANTED' $ns) } }
                $selected = [string[]]$Namespace
            }
            else { $selected = $granted }
            # The key file NeverLost issued (verified above): its comment decides TEST_ONLY refusal.
            $sourceFile = [System.IO.Path]::Combine($BundleRoot, ([string]$key['pubkey_path']).Replace('/', [string][System.IO.Path]::DirectorySeparatorChar))
            $registered = Register-WtProducer -Root $Root -Principal $Principal -KeyId ([string]$key['key_id']) -PublicKey $sourceFile -Namespace $selected -AllowTestKey:$AllowTestKey
            [void]$enrolled.Add($registered)
        }
    }
    catch {
        $failure = $_
        # All or nothing: a refusal after some keys were enrolled restores the trust state.
        if ($null -ne $snapshot) {
            Write-WtBytes -Path $layout.TrustBundle -Bytes $snapshot.Bundle
            Write-WtBytes -Path $layout.AllowedSigners -Bytes $snapshot.Signers
            foreach ($file in @(Get-ChildItem -LiteralPath $keysDirectory -File -ErrorAction SilentlyContinue)) {
                if ($snapshot.Keys -cnotcontains $file.Name) { Remove-Item -LiteralPath $file.FullName -Force }
            }
        }
        try { [void](& $record 'failed' (Get-WtFailureCode $failure)) }
        catch { Write-Verbose ('integration receipt not written: ' + (Get-WtFailureMessage $_)) }
        throw $failure
    }
    $written = & $record 'ok' ''
    return [pscustomobject]@{ Principal = $Principal; Enrolled = $enrolled.ToArray(); IntegrationReceiptSha256 = $written.ReceiptSha256; BundleSha256 = $responseSha }
}
