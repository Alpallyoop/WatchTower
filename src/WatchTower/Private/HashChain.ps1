# Append-only, hash-chained NDJSON ledgers (WatchTower ledger.md rule).
#
#   line  = canonical JSON of the row (including prev and hash fields) + LF
#   hash  = sha256(canonical_json(row without the hash field) + LF)
#   prev  = previous row's hash, or "GENESIS" for the first row
#
# Opening a ledger verifies every line; any edit, reordering, partial line,
# CR, BOM or non-canonical line fails closed. Rows are never rewritten.

function Get-WtHashChainEntryHash {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Row, [Parameter(Mandatory = $true)][string]$HashField)
    $copy = New-WtObject
    foreach ($key in $Row.PSBase.Keys) { if ([string]$key -cne $HashField) { $copy.Add([string]$key, $Row[$key]) } }
    return Get-WtCanonicalHash $copy
}

function Open-WtHashChain {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$HashField = 'receipt_hash',
        [string]$PrevField = 'prev_receipt_hash'
    )
    $chain = [pscustomobject]@{
        Path = $Path; HashField = $HashField; PrevField = $PrevField
        Count = 0; Head = 'GENESIS'; Rows = (New-Object System.Collections.ArrayList)
    }
    if (-not [System.IO.File]::Exists($Path)) { return $chain }
    $text = Read-WtText $Path
    if ($text.Length -eq 0) { return $chain }
    if ($text.Contains("`r")) { throw (New-WtFailure 'CHAIN_CR_FORBIDDEN' $Path) }
    if (-not $text.EndsWith("`n")) { throw (New-WtFailure 'CHAIN_PARTIAL_LINE' $Path) }
    $previous = 'GENESIS'
    $number = 0
    foreach ($line in $text.Substring(0, $text.Length - 1).Split("`n")) {
        $number++
        $where = '{0}:{1}' -f $Path, $number
        if ($line.Length -eq 0) { throw (New-WtFailure 'CHAIN_EMPTY_LINE' $where) }
        try { $row = ConvertFrom-WtJson $line } catch { throw (New-WtFailure 'CHAIN_BAD_LINE' ('{0} {1}' -f $where, (Get-WtFailureCode $_))) }
        if (-not ($row -is [System.Collections.IDictionary])) { throw (New-WtFailure 'CHAIN_BAD_LINE' $where) }
        if ((ConvertTo-WtCanonicalJson $row) -cne $line) { throw (New-WtFailure 'CHAIN_LINE_NOT_CANONICAL' $where) }
        if (-not $row.Contains($HashField) -or -not $row.Contains($PrevField)) { throw (New-WtFailure 'CHAIN_FIELDS_MISSING' $where) }
        if ([string]$row[$PrevField] -cne $previous) { throw (New-WtFailure 'CHAIN_LINK_BROKEN' $where) }
        $hash = Get-WtHashChainEntryHash -Row $row -HashField $HashField
        if ([string]$row[$HashField] -cne $hash) { throw (New-WtFailure 'CHAIN_HASH_MISMATCH' $where) }
        $previous = $hash
        [void]$chain.Rows.Add($row)
    }
    $chain.Count = $number
    $chain.Head = $previous
    return $chain
}

function Add-WtHashChainEntry {
    # Links, hashes and durably appends $Row to an opened chain; returns the hash.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Chain, [Parameter(Mandatory = $true)]$Row)
    if ($Row.Contains($Chain.HashField)) { $Row.Remove($Chain.HashField) }
    $Row[$Chain.PrevField] = $Chain.Head
    $hash = Get-WtHashChainEntryHash -Row $Row -HashField $Chain.HashField
    $Row[$Chain.HashField] = $hash
    Add-WtLine -Path $Chain.Path -Line (ConvertTo-WtCanonicalJson $Row)
    $Chain.Count = $Chain.Count + 1
    $Chain.Head = $hash
    [void]$Chain.Rows.Add($Row)
    return $hash
}
