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

    if ([System.IO.File]::Exists($layout.TrustBundle)) {
        $bundle = Read-WtTrustBundle $layout.TrustBundle
        $authority = Find-WtTrustKey -Bundle $bundle -Principal $script:WtAuthorityPrincipal -KeyId $script:WtAuthorityKeyId
        if ($null -eq $authority) { throw (New-WtFailure 'TRUST_AUTHORITY_MISSING' $layout.TrustBundle) }
        if ([string]$authority['pubkey'] -cne $publicKey) { throw (New-WtFailure 'TRUST_AUTHORITY_KEY_MISMATCH' 'bundle and proofs/keys disagree; rotate explicitly') }
    }
    else {
        $key = New-WtObject
        $key['key_id'] = $script:WtAuthorityKeyId
        $key['alg'] = 'ssh-ed25519'
        $key['pubkey'] = $publicKey
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
        (TEST_ONLY) are refused unless -AllowTestKey is given.
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
    $bundle = Read-WtTrustBundle $layout.TrustBundle
    if ($Principal -ceq $script:WtAuthorityPrincipal) { throw (New-WtFailure 'TRUST_PRODUCER_IS_AUTHORITY') }
    $line = $PublicKey
    if ([System.IO.File]::Exists($PublicKey)) { $line = Read-WtText $PublicKey }
    if (-not $AllowTestKey -and $line -match 'TEST_ONLY') { throw (New-WtFailure 'TRUST_TEST_KEY_REFUSED' $KeyId) }
    $canonicalKey = ConvertTo-WtPublicKey $line
    $namespaces = [string[]]@($Namespace)
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

    $key = New-WtObject
    $key['key_id'] = $KeyId
    $key['alg'] = 'ssh-ed25519'
    $key['pubkey'] = $canonicalKey
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
    $bundle = Copy-WtJsonValue $bundle
    Assert-WtTrustBundle $bundle
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
    $bundle = Read-WtTrustBundle $layout.TrustBundle
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
