# Constellation integration receipts (constellation.integration.receipt.v1).
#
# Constellation shared invariant (proposal 0013): every registered integration writes a receipt
# for every exchange, including failed ones, locally first; NFL then witnesses its hash, and
# witnessing never blocks the integration. WatchTower is the consumer, and therefore the emitter,
# in these registered integrations:
#
#   watchtower > arbiter    policy.decision.v1        one receipt per policy evaluation (ingest)
#   watchtower > neverlost  neverlost.trust_bundle.v1 one receipt per enrolment from a NeverLost bundle
#   watchtower > nfl        nfl.tier0.selftest.v1     one receipt per NFL handoff bundle consumed
#
# Line format (the Constellation schema; the same bytes HAAI emits for haai > hashcanon):
#   keys in the schema's property order (not sorted), compact, UTF-8, LF, no timestamps
#   receipt_sha256 = sha256(line without its LF)        the value a witness commits
#   prev_sha256    = previous line's receipt_sha256, 64 zeros for the first line
# One ledger per integration: proofs/integrations/<consumer>__<provider>.ndjson.
# Appends hold the ledger file exclusively, re-verify every existing line, then write one flushed
# line: a ledger is never extended past a defect.

$script:WtIntegrationReceiptSchema = 'constellation.integration.receipt.v1'
$script:WtIntegrationKeyOrder = @('schema', 'consumer', 'provider', 'emitted_by', 'contract', 'request_sha256',
    'response_sha256', 'carried', 'outcome', 'error_token', 'prev_sha256')
$script:WtIntegrationOutcomes = @('ok', 'refused', 'unavailable', 'unknown', 'deferred', 'failed')
$script:WtIntegrationGenesis = '0000000000000000000000000000000000000000000000000000000000000000'
$script:WtIntegrationServicePattern = '^[a-z0-9][a-z0-9-]*$'
$script:WtIntegrationContractPattern = '^[a-z0-9][a-z0-9_.-]*\.v[0-9]+$'
$script:WtIntegrationTokenPattern = '^[A-Z][A-Z0-9_]*$'

# The integrations WatchTower emits receipts for (registry/integrations.json, consumer = watchtower).
$script:WtIntegrations = [ordered]@{
    'arbiter'   = 'policy.decision.v1'
    'neverlost' = 'neverlost.trust_bundle.v1'
    'nfl'       = 'nfl.tier0.selftest.v1'
}

function Get-WtIntegrationLedgerPath {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)][string]$Provider, [string]$Consumer = 'watchtower')
    return [System.IO.Path]::Combine($Layout.Integrations, ('{0}__{1}.ndjson' -f $Consumer, $Provider))
}

function Assert-WtIntegrationReceipt {
    # Every rule of constellation.integration.receipt.v1, checked by hand (fails closed).
    param([Parameter(Mandatory = $true)][AllowNull()]$Receipt, [string]$Where = 'integration receipt')
    $bad = { param([string]$Why) throw (New-WtFailure 'INTEGRATION_RECEIPT_INVALID' ('{0}: {1}' -f $Where, $Why)) }
    if ($Receipt -isnot [System.Collections.IDictionary]) { & $bad 'not an object' }
    $keys = [string[]]@($Receipt.PSBase.Keys | ForEach-Object { [string]$_ })
    if ($keys.Length -ne $script:WtIntegrationKeyOrder.Length) { & $bad 'keys' }
    foreach ($key in $script:WtIntegrationKeyOrder) { if (-not $Receipt.Contains($key)) { & $bad ('missing ' + $key) } }
    if (-not ($Receipt['schema'] -is [string]) -or $Receipt['schema'] -cne $script:WtIntegrationReceiptSchema) { & $bad 'schema' }
    foreach ($key in @('consumer', 'provider')) {
        if (-not ($Receipt[$key] -is [string]) -or $Receipt[$key] -cnotmatch $script:WtIntegrationServicePattern) { & $bad $key }
    }
    # Every comparison is type-guarded: a JSON array on the left of -cne / -cnotcontains would
    # filter instead of compare and let a malformed line through.
    if (-not ($Receipt['emitted_by'] -is [string]) -or @('consumer', 'provider') -cnotcontains $Receipt['emitted_by']) { & $bad 'emitted_by' }
    $contract = $Receipt['contract']
    if ($null -ne $contract -and (-not ($contract -is [string]) -or $contract -cnotmatch $script:WtIntegrationContractPattern)) { & $bad 'contract' }
    foreach ($key in @('request_sha256', 'response_sha256')) {
        $value = $Receipt[$key]
        if ($null -ne $value -and -not ($value -is [string] -and (Test-WtHex64 $value))) { & $bad $key }
    }
    $carried = $Receipt['carried']
    if (-not ($carried -is [System.Collections.IList]) -or $carried -is [System.Collections.IDictionary]) { & $bad 'carried' }
    foreach ($item in $carried) {
        if ($item -isnot [System.Collections.IDictionary] -or $item.Count -ne 2 -or -not $item.Contains('contract') -or -not $item.Contains('sha256')) { & $bad 'carried item' }
        if (-not ($item['contract'] -is [string]) -or $item['contract'] -cnotmatch $script:WtIntegrationContractPattern) { & $bad 'carried contract' }
        if (-not ($item['sha256'] -is [string] -and (Test-WtHex64 $item['sha256']))) { & $bad 'carried sha256' }
    }
    if (-not ($Receipt['outcome'] -is [string]) -or $script:WtIntegrationOutcomes -cnotcontains $Receipt['outcome']) { & $bad 'outcome' }
    $token = $Receipt['error_token']
    if (([string]$Receipt['outcome'] -ceq 'ok') -ne ($null -eq $token)) { & $bad 'error_token must be null exactly when outcome is ok' }
    if ($null -ne $token -and (-not ($token -is [string]) -or $token -cnotmatch $script:WtIntegrationTokenPattern)) { & $bad 'error_token' }
    if (-not ($Receipt['prev_sha256'] -is [string] -and (Test-WtHex64 $Receipt['prev_sha256']))) { & $bad 'prev_sha256' }
}

function ConvertTo-WtIntegrationLine {
    # The receipt in the schema's key order, compact, without the trailing LF. Values are
    # serialized canonically (carried items {contract, sha256} are already in sorted order).
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Receipt)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('{')
    $first = $true
    foreach ($key in $script:WtIntegrationKeyOrder) {
        if (-not $first) { [void]$builder.Append(',') }
        $first = $false
        [void]$builder.Append((ConvertTo-WtCanonicalJson $key)).Append(':').Append((ConvertTo-WtCanonicalJson $Receipt[$key]))
    }
    [void]$builder.Append('}')
    return $builder.ToString()
}

function Read-WtIntegrationLedger {
    # Verifies every line from bytes: strict JSON, schema rules, exact serialization and the chain.
    # A writer holds the file exclusively for a moment; reads retry briefly instead of failing.
    param([Parameter(Mandatory = $true)][string]$Path)
    $ledger = [pscustomobject]@{ Path = $Path; Count = 0; Head = $script:WtIntegrationGenesis; Rows = (New-Object System.Collections.ArrayList); Hashes = (New-Object System.Collections.ArrayList); Lines = (New-Object System.Collections.ArrayList) }
    if (-not [System.IO.File]::Exists($Path)) { return $ledger }
    $holder = @{ Bytes = $null }
    Invoke-WtFsRetry { $holder.Bytes = [System.IO.File]::ReadAllBytes($Path) }
    return (ConvertFrom-WtIntegrationLedgerBytes -Bytes $holder.Bytes -Path $Path)
}

# Per-process cache of verified ledger tails, so an ingest of n packets does not re-parse the
# whole arbiter ledger n times. An entry is trusted only while the file still has exactly the
# cached length AND its last line still hashes to the cached head; anything else re-verifies the
# whole file. Test-WtLedger always re-verifies from scratch.
$script:WtIntegrationTail = @{}

function Get-WtIntegrationTail {
    param([Parameter(Mandatory = $true)][System.IO.FileStream]$Stream, [Parameter(Mandatory = $true)][string]$Path)
    $length = $Stream.Length
    if ($script:WtIntegrationTail.ContainsKey($Path)) {
        $cached = $script:WtIntegrationTail[$Path]
        if ($cached.Length -eq $length -and $cached.LastLineLength -gt 0 -and $cached.LastLineLength -le $length) {
            $buffer = New-Object byte[] ([int]$cached.LastLineLength)
            [void]$Stream.Seek($length - $cached.LastLineLength, [System.IO.SeekOrigin]::Begin)
            $read = 0
            while ($read -lt $buffer.Length) { $n = $Stream.Read($buffer, $read, $buffer.Length - $read); if ($n -le 0) { break }; $read += $n }
            if ($read -eq $buffer.Length -and $buffer[$buffer.Length - 1] -eq 10) {
                $line = ConvertFrom-WtUtf8 -Bytes ([byte[]]$buffer[0..($buffer.Length - 2)]) -Source $Path
                if (-not $line.Contains("`n") -and (Get-WtSha256 -Text $line) -ceq $cached.Head) { return $cached }
            }
        }
    }
    $bytes = New-Object byte[] ([int]$length)
    [void]$Stream.Seek(0, [System.IO.SeekOrigin]::Begin)
    $read = 0
    while ($read -lt $bytes.Length) { $n = $Stream.Read($bytes, $read, $bytes.Length - $read); if ($n -le 0) { break }; $read += $n }
    $ledger = ConvertFrom-WtIntegrationLedgerBytes -Bytes $bytes -Path $Path
    $lastLength = 0
    if ($ledger.Count -gt 0) { $lastLength = (ConvertTo-WtUtf8 ([string]$ledger.Lines[$ledger.Count - 1])).Length + 1 }
    return [pscustomobject]@{ Length = $length; Count = $ledger.Count; Head = $ledger.Head; LastLineLength = $lastLength }
}

function ConvertFrom-WtIntegrationLedgerBytes {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$Path)
    $ledger = [pscustomobject]@{ Path = $Path; Count = 0; Head = $script:WtIntegrationGenesis; Rows = (New-Object System.Collections.ArrayList); Hashes = (New-Object System.Collections.ArrayList); Lines = (New-Object System.Collections.ArrayList) }
    if ($Bytes.Length -eq 0) { return $ledger }
    $text = ConvertFrom-WtUtf8 -Bytes $Bytes -Source $Path
    if ($text.Contains("`r")) { throw (New-WtFailure 'INTEGRATION_LEDGER_CR' $Path) }
    if (-not $text.EndsWith("`n")) { throw (New-WtFailure 'INTEGRATION_LEDGER_PARTIAL' $Path) }
    $previous = $script:WtIntegrationGenesis
    $number = 0
    foreach ($line in $text.Substring(0, $text.Length - 1).Split("`n")) {
        $number++
        $where = '{0}:{1}' -f [System.IO.Path]::GetFileName($Path), $number
        if ($line.Length -eq 0) { throw (New-WtFailure 'INTEGRATION_LEDGER_EMPTY_LINE' $where) }
        try { $row = ConvertFrom-WtJson $line } catch { throw (New-WtFailure 'INTEGRATION_LEDGER_BAD_JSON' ('{0} {1}' -f $where, (Get-WtFailureCode $_))) }
        Assert-WtIntegrationReceipt -Receipt $row -Where $where
        if ((ConvertTo-WtIntegrationLine $row) -cne $line) { throw (New-WtFailure 'INTEGRATION_LEDGER_NONCANONICAL' $where) }
        if ([string]$row['prev_sha256'] -cne $previous) { throw (New-WtFailure 'INTEGRATION_LEDGER_CHAIN_MISMATCH' $where) }
        $previous = Get-WtSha256 -Text $line
        [void]$ledger.Rows.Add($row)
        [void]$ledger.Hashes.Add($previous)
        [void]$ledger.Lines.Add($line)
    }
    $ledger.Count = $number
    $ledger.Head = $previous
    return $ledger
}

function New-WtIntegrationReceipt {
    # A receipt body (without prev_sha256) for an exchange where WatchTower is the consumer.
    param(
        [Parameter(Mandatory = $true)][string]$Provider,
        [Parameter(Mandatory = $true)][string]$Contract,
        [AllowNull()][AllowEmptyString()][string]$RequestSha256,
        [AllowNull()][AllowEmptyString()][string]$ResponseSha256,
        [Parameter(Mandatory = $true)][ValidateSet('ok', 'refused', 'unavailable', 'unknown', 'deferred', 'failed')][string]$Outcome,
        [AllowNull()][AllowEmptyString()][string]$ErrorToken,
        [object[]]$Carried = @()
    )
    $receipt = New-WtObject
    $receipt['schema'] = $script:WtIntegrationReceiptSchema
    $receipt['consumer'] = 'watchtower'
    $receipt['provider'] = $Provider
    $receipt['emitted_by'] = 'consumer'
    $receipt['contract'] = $Contract
    $receipt['request_sha256'] = $(if ($RequestSha256) { $RequestSha256 } else { $null })
    $receipt['response_sha256'] = $(if ($ResponseSha256) { $ResponseSha256 } else { $null })
    $items = New-Object System.Collections.ArrayList
    foreach ($item in $Carried) {
        $entry = New-WtObject
        $entry['contract'] = [string]$item.Contract
        $entry['sha256'] = [string]$item.Sha256
        [void]$items.Add($entry)
    }
    $receipt['carried'] = $items
    $receipt['outcome'] = $Outcome
    $receipt['error_token'] = $(if ($Outcome -ceq 'ok') { $null } elseif ($ErrorToken) { $ErrorToken } else { 'UNSPECIFIED' })
    $receipt['prev_sha256'] = $script:WtIntegrationGenesis
    return , $receipt
}

function Add-WtIntegrationReceipt {
    # Durable, verified append. Holds the ledger exclusively for the whole read-verify-append, so
    # two writers can never fork the chain. Returns the receipt, its sha256 and its index.
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Receipt)
    $path = Get-WtIntegrationLedgerPath -Layout $Layout -Provider ([string]$Receipt['provider']) -Consumer ([string]$Receipt['consumer'])
    New-WtDirectory ([System.IO.Path]::GetDirectoryName($path))
    # Exclusive open (FileShare.None) is the writer lock; a concurrent writer retries briefly.
    $holder = @{ Stream = $null }
    Invoke-WtFsRetry { $holder.Stream = New-Object System.IO.FileStream($path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) }
    $stream = $holder.Stream
    try {
        $tail = Get-WtIntegrationTail -Stream $stream -Path $path
        $Receipt['prev_sha256'] = $tail.Head
        Assert-WtIntegrationReceipt -Receipt $Receipt -Where 'new receipt'
        $line = ConvertTo-WtIntegrationLine $Receipt
        $bytes = ConvertTo-WtUtf8 ($line + "`n")
        [void]$stream.Seek(0, [System.IO.SeekOrigin]::End)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        # Re-read what was written before releasing the file.
        $check = New-Object byte[] ($bytes.Length)
        [void]$stream.Seek($tail.Length, [System.IO.SeekOrigin]::Begin)
        $read = 0
        while ($read -lt $check.Length) { $n = $stream.Read($check, $read, $check.Length - $read); if ($n -le 0) { break }; $read += $n }
        if ($stream.Length -ne $tail.Length + $bytes.Length -or (Get-WtSha256 -Bytes $check) -cne (Get-WtSha256 -Bytes $bytes)) { throw (New-WtFailure 'INTEGRATION_LEDGER_APPEND_VERIFY' $path) }
    }
    catch { $script:WtIntegrationTail.Remove($path); throw }
    finally { $stream.Dispose() }
    $hash = Get-WtSha256 -Text $line
    $script:WtIntegrationTail[$path] = [pscustomobject]@{ Length = $tail.Length + $bytes.Length; Count = $tail.Count + 1; Head = $hash; LastLineLength = $bytes.Length }
    return [pscustomobject]@{
        Receipt = $Receipt; ReceiptSha256 = $hash; Index = $tail.Count + 1
        WitnessLabel = '{0}:{1}>{2}' -f $script:WtIntegrationReceiptSchema, $Receipt['consumer'], $Receipt['provider']
        Ledger = Get-WtRootRelative $Layout $path
    }
}

function Get-WtIntegrationLedgers {
    # Every integration ledger present under proofs/integrations, ordinal by file name.
    param([Parameter(Mandatory = $true)]$Layout)
    $paths = @()
    if ([System.IO.Directory]::Exists($Layout.Integrations)) {
        $paths = [string[]]@([System.IO.Directory]::GetFiles($Layout.Integrations, '*__*.ndjson'))
        [Array]::Sort($paths, [System.StringComparer]::Ordinal)
    }
    return , $paths
}

#region NFL witness packets

function Publish-WtIntegrationWitness {
    # Hands every integration receipt not yet witnessed to NFL: one PCv1 Option A packet in
    # packets/outbox (NFL polls it and commits the packet hash after CPR verification), then one
    # row in the witness ledger proofs/integrations/watchtower.integration_witness.v1.ndjson.
    # Returns $null when there is nothing new. Never blocks or alters an integration.
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Authority, [Parameter(Mandatory = $true)][string]$VerifiedUtc)
    $witness = Open-WtHashChain -Path $Layout.IntegrationWitnessLedger -HashField 'witness_hash' -PrevField 'prev_witness_hash'
    $witnessed = @{}
    foreach ($row in $witness.Rows) { foreach ($entry in $row['ledgers']) { $witnessed[[string]$entry['integration']] = [long]$entry['last_index'] } }

    $entries = New-Object System.Collections.ArrayList
    $payload = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::Ordinal)
    foreach ($path in (Get-WtIntegrationLedgers $Layout)) {
        $ledger = Read-WtIntegrationLedger $path
        $name = [System.IO.Path]::GetFileNameWithoutExtension($path)
        $integration = $name.Replace('__', '>')
        $done = 0
        if ($witnessed.ContainsKey($integration)) { $done = [long]$witnessed[$integration] }
        if ($done -gt $ledger.Count) { throw (New-WtFailure 'INTEGRATION_WITNESS_AHEAD' $integration) }
        if ($ledger.Count -le $done) { continue }
        $slice = New-Object System.Text.StringBuilder
        $hashes = New-Object System.Collections.ArrayList
        for ($i = $done; $i -lt $ledger.Count; $i++) {
            [void]$slice.Append([string]$ledger.Lines[$i]).Append("`n")
            [void]$hashes.Add([string]$ledger.Hashes[$i])
        }
        $file = 'integration_receipts/' + $name + '.ndjson'
        $payload[$file] = $slice.ToString()
        $entry = New-WtObject
        $entry['integration'] = $integration
        $entry['ledger'] = Get-WtRootRelative $Layout $path
        $entry['payload'] = 'payload/' + $file
        $entry['first_index'] = $done + 1
        $entry['last_index'] = [long]$ledger.Count
        $entry['prev_sha256'] = $(if ($done -eq 0) { $script:WtIntegrationGenesis } else { [string]$ledger.Hashes[$done - 1] })
        $entry['head_sha256'] = $ledger.Head
        $entry['receipt_sha256'] = $hashes
        [void]$entries.Add($entry)
    }
    if ($entries.Count -eq 0) { return $null }

    $files = New-Object System.Collections.ArrayList
    foreach ($name in $payload.PSBase.Keys) {
        $item = New-WtObject
        $item['path'] = 'payload/' + $name
        $item['sha256'] = Get-WtSha256 -Text ([string]$payload[$name])
        [void]$files.Add($item)
    }
    $manifest = New-WtObject
    $manifest['schema'] = $script:WtIntegrationWitnessSchema
    $manifest['constitution'] = 'packet_constitution_v1_option_a'
    $manifest['kind'] = 'integration_receipts'
    $manifest['receipt_schema'] = $script:WtIntegrationReceiptSchema
    $manifest['producer'] = $Authority.Principal
    $manifest['producer_instance'] = $Authority.NodeId
    $manifest['created_time'] = $VerifiedUtc
    $manifest['ledgers'] = $entries
    $manifest['files'] = $files
    $context = [pscustomobject]@{ Authority = $Authority }
    $sign = {
        param([string]$Build, [string]$PacketId, $Context)
        New-WtAuthoritySignature -Authority $Context.Authority -Namespace $script:WtNamespaceEnvelope -MessagePath (Join-Path $Build 'manifest.json') -SignaturePath (Join-Path (Join-Path $Build 'signatures') 'manifest.sig')
    }
    $packet = New-WtPacket -OutputDirectory $Layout.Outbox -Manifest $manifest -Payload $payload -Signatures $sign -SignatureContext $context

    $row = New-WtObject
    $row['schema'] = $script:WtIntegrationWitnessRecordSchema
    $row['witness_time'] = $VerifiedUtc
    $row['verifier'] = $Authority.Principal
    $row['node_id'] = $Authority.NodeId
    $row['outbox_packet_id'] = $packet.PacketId
    $summary = New-Object System.Collections.ArrayList
    foreach ($entry in $entries) {
        $item = New-WtObject
        foreach ($key in @('integration', 'first_index', 'last_index', 'head_sha256')) { $item[$key] = $entry[$key] }
        [void]$summary.Add($item)
    }
    $row['ledgers'] = $summary
    [void](Add-WtHashChainEntry -Chain $witness -Row $row)
    return [pscustomobject]@{ PacketId = $packet.PacketId; Ledgers = $entries.Count; Receipts = (@($entries | ForEach-Object { $_['receipt_sha256'].Count }) | Measure-Object -Sum).Sum }
}

function Test-WtIntegrationEvidence {
    # Re-verifies every integration ledger and the witness ledger: each witness row names a
    # contiguous, existing range whose head matches the ledger, and its outbox packet (when still
    # present) verifies and carries those exact lines. Returns counts; throws on any defect.
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Warnings, $Bundle = $null)
    $ledgers = @{}
    $counts = New-Object System.Collections.ArrayList
    foreach ($path in (Get-WtIntegrationLedgers $Layout)) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($path)
        try { $ledger = Read-WtIntegrationLedger $path }
        catch { throw (New-WtFailure 'LEDGER_INTEGRATION_INVALID' ('{0}: {1}' -f $name, (Get-WtFailureMessage $_))) }
        foreach ($row in $ledger.Rows) {
            if (('{0}__{1}' -f $row['consumer'], $row['provider']) -cne $name) { throw (New-WtFailure 'LEDGER_INTEGRATION_MISFILED' $name) }
        }
        $ledgers[$name.Replace('__', '>')] = $ledger
        [void]$counts.Add([pscustomobject]@{ Integration = $name.Replace('__', '>'); Count = $ledger.Count; Head = $ledger.Head })
    }
    $witness = Open-WtHashChain -Path $Layout.IntegrationWitnessLedger -HashField 'witness_hash' -PrevField 'prev_witness_hash'
    $next = @{}
    foreach ($row in $witness.Rows) {
        if ([string]$row['schema'] -cne $script:WtIntegrationWitnessRecordSchema) { throw (New-WtFailure 'LEDGER_WITNESS_SCHEMA' $row['witness_hash']) }
        foreach ($entry in $row['ledgers']) {
            $integration = [string]$entry['integration']
            if (-not $ledgers.ContainsKey($integration)) { throw (New-WtFailure 'LEDGER_WITNESS_UNKNOWN_INTEGRATION' $integration) }
            $ledger = $ledgers[$integration]
            $expectedFirst = $(if ($next.ContainsKey($integration)) { $next[$integration] } else { 1 })
            $first = [long]$entry['first_index']; $last = [long]$entry['last_index']
            if ($first -ne $expectedFirst -or $last -lt $first -or $last -gt $ledger.Count) { throw (New-WtFailure 'LEDGER_WITNESS_RANGE' $integration) }
            if ([string]$ledger.Hashes[$last - 1] -cne [string]$entry['head_sha256']) { throw (New-WtFailure 'LEDGER_WITNESS_HEAD' $integration) }
            $next[$integration] = $last + 1
        }
        $packetId = [string]$row['outbox_packet_id']
        $packetPath = Join-Path $Layout.Outbox $packetId
        if (-not [System.IO.Directory]::Exists($packetPath)) { [void]$Warnings.Add('OUTBOX_PACKET_ABSENT ' + $packetId); continue }
        if (-not (Test-WtPacket $packetPath).Valid) { throw (New-WtFailure 'LEDGER_WITNESS_PACKET_INVALID' $packetId) }
        $manifestPath = Join-Path $packetPath 'manifest.json'
        if ($null -ne $Bundle -and -not (Test-WtAuthoritySignature -Bundle $Bundle -Namespace $script:WtNamespaceEnvelope -SignaturePath (Join-Path $packetPath 'signatures/manifest.sig') -MessagePath $manifestPath)) {
            throw (New-WtFailure 'LEDGER_WITNESS_PACKET_SIGNATURE' $packetId)
        }
        $manifest = Read-WtJsonFile -Path $manifestPath -Object -Canonical
        # The packet carries exactly the ranges its witness row claims.
        $claimed = @($row['ledgers'] | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_['integration'], $_['first_index'], $_['last_index'], $_['head_sha256'] }) -join ';'
        $carriedRanges = @($manifest['ledgers'] | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_['integration'], $_['first_index'], $_['last_index'], $_['head_sha256'] }) -join ';'
        if ($claimed -cne $carriedRanges) { throw (New-WtFailure 'LEDGER_WITNESS_PACKET_CONTENT' $packetId) }
        foreach ($entry in $manifest['ledgers']) {
            $ledger = $ledgers[[string]$entry['integration']]
            if ($null -eq $ledger) { throw (New-WtFailure 'LEDGER_WITNESS_PACKET_CONTENT' $packetId) }
            Assert-WtSafeRelativePath ([string]$entry['payload'])
            $hashes = @($entry['receipt_sha256'] | ForEach-Object { [string]$_ }) -join ','
            $expectedHashes = @(for ($i = [long]$entry['first_index']; $i -le [long]$entry['last_index']; $i++) { [string]$ledger.Hashes[$i - 1] }) -join ','
            if ($hashes -cne $expectedHashes) { throw (New-WtFailure 'LEDGER_WITNESS_PACKET_CONTENT' $packetId) }
            $expected = New-Object System.Text.StringBuilder
            for ($i = [long]$entry['first_index']; $i -le [long]$entry['last_index']; $i++) { [void]$expected.Append([string]$ledger.Lines[$i - 1]).Append("`n") }
            $carried = Read-WtText (Join-Path $packetPath ([string]$entry['payload']))
            if ($carried -cne $expected.ToString()) { throw (New-WtFailure 'LEDGER_WITNESS_PACKET_CONTENT' $packetId) }
        }
    }
    $names = [string[]]@($ledgers.Keys)
    [Array]::Sort($names, [System.StringComparer]::Ordinal)
    foreach ($integration in $names) {
        $done = $(if ($next.ContainsKey($integration)) { $next[$integration] - 1 } else { 0 })
        if ($done -lt $ledgers[$integration].Count) { [void]$Warnings.Add(('INTEGRATION_RECEIPTS_UNWITNESSED {0} {1}' -f $integration, ($ledgers[$integration].Count - $done))) }
    }
    return [pscustomobject]@{ Integrations = $counts.ToArray(); Witness = [pscustomobject]@{ Count = $witness.Count; Head = $witness.Head } }
}

#endregion
