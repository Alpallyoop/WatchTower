# NeverLost trust bundles (neverlost.trust_bundle.v1).
#
#   { "schema": "neverlost.trust_bundle.v1", "created_utc": "...",
#     "principals": [ { "principal": "...",
#                       "keys": [ { "key_id", "alg": "ssh-ed25519", "pubkey",
#                                   "namespaces": [...], "pubkey_sha256"?, "pubkey_path"? } ] } ] }
#
# The bundle is the single source of truth. allowed_signers is derived only;
# verification always derives a fresh, minimal allowed_signers in a private
# temp file and never trusts one found on disk or inside a packet.

$script:WtPrincipalPattern = '^[A-Za-z0-9][A-Za-z0-9._@/\-]*$'
$script:WtKeyIdPattern = '^[A-Za-z0-9][A-Za-z0-9._\-]*$'
$script:WtNamespacePattern = '^[a-z0-9][a-z0-9._/\-]*$'

function Assert-WtTrustBundle {
    param([Parameter(Mandatory = $true)][AllowNull()]$Bundle, [string]$Source = 'trust_bundle')
    if (-not ($Bundle -is [System.Collections.IDictionary])) { throw (New-WtFailure 'TRUST_BUNDLE_NOT_OBJECT' $Source) }
    $schema = Get-WtField $Bundle 'schema' 'string' $Source
    if ($schema -cne 'neverlost.trust_bundle.v1') { throw (New-WtFailure 'TRUST_BUNDLE_SCHEMA' $schema) }
    $principals = Get-WtField $Bundle 'principals' 'array' $Source
    if ($principals.Count -lt 1) { throw (New-WtFailure 'TRUST_BUNDLE_EMPTY' $Source) }
    $seenPrincipals = @{}
    $seenKeys = @{}
    # Key ids are unique across the whole bundle (NeverLost v1 rule KEY_ID_DUPLICATE), not only
    # within a principal: an allowed_signers consumer must never see one key id twice.
    $seenKeyIds = @{}
    foreach ($entry in $principals) {
        $principal = Get-WtField $entry 'principal' 'text' $Source
        if ($principal -cnotmatch $script:WtPrincipalPattern) { throw (New-WtFailure 'TRUST_PRINCIPAL_FORMAT' $principal) }
        if ($seenPrincipals.ContainsKey($principal)) { throw (New-WtFailure 'TRUST_DUPLICATE_PRINCIPAL' $principal) }
        $seenPrincipals[$principal] = $true
        $keys = Get-WtField $entry 'keys' 'array' $principal
        if ($keys.Count -lt 1) { throw (New-WtFailure 'TRUST_PRINCIPAL_NO_KEYS' $principal) }
        foreach ($key in $keys) {
            $keyId = Get-WtField $key 'key_id' 'text' $principal
            if ($keyId -cnotmatch $script:WtKeyIdPattern) { throw (New-WtFailure 'TRUST_KEY_ID_FORMAT' $keyId) }
            if ($seenKeyIds.ContainsKey($keyId)) { throw (New-WtFailure 'TRUST_DUPLICATE_KEY_ID' ($principal + '/' + $keyId)) }
            $seenKeyIds[$keyId] = $true
            if ((Get-WtField $key 'alg' 'string' $keyId) -cne 'ssh-ed25519') { throw (New-WtFailure 'TRUST_KEY_ALG' $keyId) }
            $publicKey = Get-WtField $key 'pubkey' 'string' $keyId
            if ($publicKey -cne (ConvertTo-WtPublicKey $publicKey)) { throw (New-WtFailure 'TRUST_PUBKEY_NOT_CANONICAL' $keyId) }
            if ($seenKeys.ContainsKey($publicKey)) { throw (New-WtFailure 'TRUST_PUBKEY_REUSED' $keyId) }
            $seenKeys[$publicKey] = $true
            $namespaces = Get-WtField $key 'namespaces' 'array' $keyId
            if ($namespaces.Count -lt 1) { throw (New-WtFailure 'TRUST_KEY_NO_NAMESPACES' $keyId) }
            $seenNamespaces = @{}
            foreach ($namespace in $namespaces) {
                if (-not ($namespace -is [string]) -or $namespace -cnotmatch $script:WtNamespacePattern) { throw (New-WtFailure 'TRUST_NAMESPACE_FORMAT' ([string]$namespace)) }
                if ($seenNamespaces.ContainsKey($namespace)) { throw (New-WtFailure 'TRUST_DUPLICATE_NAMESPACE' $namespace) }
                $seenNamespaces[$namespace] = $true
            }
            if ((Test-WtField $key 'pubkey_sha256') -and -not (Test-WtHex64 ([string]$key['pubkey_sha256']))) { throw (New-WtFailure 'TRUST_PUBKEY_SHA256_FORMAT' $keyId) }
            if (Test-WtField $key 'pubkey_path') {
                # NeverLost v1: pubkey_sha256 is the SHA-256 of the exact bytes at pubkey_path.
                $relative = Get-WtField $key 'pubkey_path' 'text' $keyId
                try { Assert-WtSafeRelativePath $relative } catch { throw (New-WtFailure 'TRUST_PUBKEY_PATH' ('{0}: {1}' -f $keyId, (Get-WtFailureCode $_))) }
                if (-not (Test-WtField $key 'pubkey_sha256')) { throw (New-WtFailure 'TRUST_PUBKEY_SHA256_MISSING' $keyId) }
            }
        }
    }
}

function Assert-WtTrustKeyMaterial {
    # Recomputes every key file claim against $Root (NeverLost NL-VerifyKeyMaterial): the file
    # at pubkey_path exists, hashes to pubkey_sha256, and holds exactly the bundle's pubkey.
    param([Parameter(Mandatory = $true)]$Bundle, [Parameter(Mandatory = $true)][string]$Root)
    foreach ($entry in $Bundle['principals']) {
        foreach ($key in $entry['keys']) {
            if (-not (Test-WtField $key 'pubkey_path')) { continue }
            $keyId = [string]$key['key_id']
            $file = [System.IO.Path]::Combine($Root, ([string]$key['pubkey_path']).Replace('/', [string][System.IO.Path]::DirectorySeparatorChar))
            if (-not [System.IO.File]::Exists($file)) { throw (New-WtFailure 'TRUST_PUBKEY_FILE_MISSING' ('{0} {1}' -f $keyId, $key['pubkey_path'])) }
            if ((Get-WtSha256 -Path $file) -cne [string]$key['pubkey_sha256']) { throw (New-WtFailure 'TRUST_PUBKEY_SHA256_MISMATCH' $keyId) }
            $core = ''
            try { $core = ConvertTo-WtPublicKey (Read-WtText $file) } catch { throw (New-WtFailure 'TRUST_PUBKEY_FILE_FORMAT' $keyId) }
            if ($core -cne [string]$key['pubkey']) { throw (New-WtFailure 'TRUST_PUBKEY_FILE_MISMATCH' $keyId) }
        }
    }
}

function Read-WtTrustBundle {
    # -Root: the directory pubkey_path entries are relative to (the state root for WatchTower's own
    # bundle); when given, every key file is re-verified.
    param([Parameter(Mandatory = $true)][string]$Path, [string]$Root = '')
    if (-not [System.IO.File]::Exists($Path)) { throw (New-WtFailure 'TRUST_BUNDLE_MISSING' $Path) }
    $bundle = Read-WtJsonFile -Path $Path -Object
    Assert-WtTrustBundle -Bundle $bundle -Source $Path
    if ($Root) { Assert-WtTrustKeyMaterial -Bundle $bundle -Root $Root }
    return , $bundle
}

function ConvertTo-WtAllowedSigners {
    # '<principal> namespaces="<ordinal-sorted,csv>" <pubkey>' per key,
    # ordered by principal + LF + pubkey (ordinal), LF-terminated.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Bundle)
    $lines = @{}
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $Bundle['principals']) {
        foreach ($key in $entry['keys']) {
            $namespaces = [string[]]@($key['namespaces'] | ForEach-Object { [string]$_ })
            [Array]::Sort($namespaces, [System.StringComparer]::Ordinal)
            $sortKey = [string]$entry['principal'] + "`n" + [string]$key['pubkey']
            $order.Add($sortKey)
            $lines[$sortKey] = '{0} namespaces="{1}" {2}' -f $entry['principal'], ($namespaces -join ','), $key['pubkey']
        }
    }
    $sorted = $order.ToArray()
    [Array]::Sort($sorted, [System.StringComparer]::Ordinal)
    $builder = New-Object System.Text.StringBuilder
    foreach ($sortKey in $sorted) { [void]$builder.Append($lines[$sortKey]).Append("`n") }
    return $builder.ToString()
}

function Find-WtTrustKey {
    # The key entry for (principal, key_id), or $null.
    param([Parameter(Mandatory = $true)]$Bundle, [Parameter(Mandatory = $true)][string]$Principal, [Parameter(Mandatory = $true)][string]$KeyId)
    foreach ($entry in $Bundle['principals']) {
        if ([string]$entry['principal'] -cne $Principal) { continue }
        foreach ($key in $entry['keys']) { if ([string]$key['key_id'] -ceq $KeyId) { return , $key } }
    }
    return $null
}

function Test-WtTrustNamespace {
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Key, [Parameter(Mandatory = $true)][string]$Namespace)
    # Note: PowerShell variable names are case-insensitive, so the loop variable
    # must not be called $namespace (it would overwrite the parameter).
    foreach ($authorized in $Key['namespaces']) { if ([string]$authorized -ceq $Namespace) { return $true } }
    return $false
}

function Test-WtTrustedSignature {
    # Verifies a detached signature against exactly one pinned trust-bundle key.
    # Fails closed if the principal/key is not enrolled or not authorised for
    # the namespace; returns $false only for a cryptographically bad signature.
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]$Bundle,
        [Parameter(Mandatory = $true)][string]$Principal,
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$Namespace,
        [Parameter(Mandatory = $true)][string]$SignaturePath,
        [Parameter(Mandatory = $true)][string]$MessagePath
    )
    $key = Find-WtTrustKey -Bundle $Bundle -Principal $Principal -KeyId $KeyId
    if ($null -eq $key) { throw (New-WtFailure 'SIGNER_NOT_TRUSTED' ('{0}/{1}' -f $Principal, $KeyId)) }
    if (-not (Test-WtTrustNamespace -Key $key -Namespace $Namespace)) { throw (New-WtFailure 'SIGNER_NAMESPACE_NOT_AUTHORIZED' ('{0} -> {1}' -f $Principal, $Namespace)) }
    $work = New-WtTempDirectory 'wtverify'
    try {
        $allowed = Join-Path $work 'allowed_signers'
        $line = ('{0} namespaces="{1}" {2}' -f $Principal, $Namespace, [string]$key['pubkey']) + "`n"
        Write-WtBytes -Path $allowed -Bytes (ConvertTo-WtUtf8 $line)
        return (Test-WtSignature -AllowedSignersPath $allowed -Principal $Principal -Namespace $Namespace -SignaturePath $SignaturePath -MessagePath $MessagePath)
    }
    finally { Remove-WtTree $work }
}
