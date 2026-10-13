# This node's signing authority: the private key on disk must match the
# authority entry in the pinned trust bundle, or nothing is signed.

function Get-WtAuthority {
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Bundle)
    if (-not [System.IO.File]::Exists($Layout.AuthorityKey)) { throw (New-WtFailure 'AUTHORITY_KEY_MISSING' 'run Initialize-WtTrust') }
    $publicKey = ConvertTo-WtPublicKey (Read-WtText ($Layout.AuthorityKey + '.pub'))
    $entry = Find-WtTrustKey -Bundle $Bundle -Principal $script:WtAuthorityPrincipal -KeyId $script:WtAuthorityKeyId
    if ($null -eq $entry) { throw (New-WtFailure 'TRUST_AUTHORITY_MISSING') }
    if ([string]$entry['pubkey'] -cne $publicKey) { throw (New-WtFailure 'TRUST_AUTHORITY_KEY_MISMATCH') }
    foreach ($namespace in $script:WtAuthorityNamespaces) {
        if (-not (Test-WtTrustNamespace -Key $entry -Namespace $namespace)) { throw (New-WtFailure 'TRUST_AUTHORITY_NAMESPACES' $namespace) }
    }
    return [pscustomobject]@{
        Principal = $script:WtAuthorityPrincipal
        KeyId     = $script:WtAuthorityKeyId
        KeyPath   = $Layout.AuthorityKey
        PublicKey = $publicKey
        NodeId    = Get-WtNodeId $publicKey
    }
}

function New-WtAuthoritySignature {
    # Detached signature over exact text (UTF-8, as given) or a file's bytes.
    param(
        [Parameter(Mandatory = $true)]$Authority,
        [Parameter(Mandatory = $true)][string]$Namespace,
        [Parameter(Mandatory = $true)][string]$SignaturePath,
        [string]$MessagePath,
        [AllowEmptyString()][string]$Text
    )
    if ($MessagePath) { New-WtSignature -KeyPath $Authority.KeyPath -Namespace $Namespace -MessagePath $MessagePath -SignaturePath $SignaturePath; return }
    $work = New-WtTempDirectory 'wtmsg'
    try {
        $message = Join-Path $work 'message'
        Write-WtBytes -Path $message -Bytes (ConvertTo-WtUtf8 $Text)
        New-WtSignature -KeyPath $Authority.KeyPath -Namespace $Namespace -MessagePath $message -SignaturePath $SignaturePath
    }
    finally { Remove-WtTree $work }
}

function Test-WtAuthoritySignature {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]$Bundle,
        [Parameter(Mandatory = $true)][string]$Namespace,
        [Parameter(Mandatory = $true)][string]$SignaturePath,
        [string]$MessagePath,
        [AllowEmptyString()][string]$Text
    )
    if (-not [System.IO.File]::Exists($SignaturePath)) { return $false }
    if ($MessagePath) {
        return Test-WtTrustedSignature -Bundle $Bundle -Principal $script:WtAuthorityPrincipal -KeyId $script:WtAuthorityKeyId -Namespace $Namespace -SignaturePath $SignaturePath -MessagePath $MessagePath
    }
    $work = New-WtTempDirectory 'wtmsg'
    try {
        $message = Join-Path $work 'message'
        Write-WtBytes -Path $message -Bytes (ConvertTo-WtUtf8 $Text)
        return Test-WtTrustedSignature -Bundle $Bundle -Principal $script:WtAuthorityPrincipal -KeyId $script:WtAuthorityKeyId -Namespace $Namespace -SignaturePath $SignaturePath -MessagePath $message
    }
    finally { Remove-WtTree $work }
}

function Get-WtSignedLine {
    # The exact bytes a ledger row signature covers: canonical JSON of the row + LF.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Row)
    return (ConvertTo-WtCanonicalJson $Row) + "`n"
}
