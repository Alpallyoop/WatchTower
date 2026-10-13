# Unit tests for the private core: JSON, canonical form, paths, native argv, signatures,
# trust bundles and hash chains.
. (Join-Path $PSScriptRoot 'support/TestHarness.ps1')
$repo = Get-WtRepoRoot
foreach ($name in @('Errors', 'IO', 'Json', 'Paths', 'Native', 'Trust', 'HashChain')) { . (Join-Path $repo ('src/WatchTower/Private/{0}.ps1' -f $name)) }
$work = New-WtTempDirectory 'wt_core_tests'

# --- strict JSON ---------------------------------------------------------------------
Invoke-WtTest 'json: canonical form matches the ecosystem rule (sorted, compact, raw UTF-8)' {
    $value = ConvertFrom-WtJson '{"b":[1,{"z":null,"a":true}],"a":"x\u00e9\n\"q\"","t":"2026-03-12T15:04:00Z"}'
    # [char]0x00E9: sources stay ASCII, because Windows PowerShell 5.1 reads BOM-less files as ANSI.
    Assert-WtEqual ('{"a":"x' + [char]0x00E9 + '\n\"q\"","b":[1,{"a":true,"z":null}],"t":"2026-03-12T15:04:00Z"}') (ConvertTo-WtCanonicalJson $value)
}
Invoke-WtTest 'sources: every v2 PowerShell file is ASCII (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
    $roots = @('src', 'bin', 'tests', 'scripts/_RUN_watchtower_canonical_full_green_v2.ps1') | ForEach-Object { Join-Path $repo $_ }
    foreach ($file in @(Get-ChildItem -LiteralPath $roots -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1' | Where-Object { $_.FullName -notmatch '[\\/](fixtures|unit|integration)[\\/]' })) {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        foreach ($b in $bytes) { if ($b -gt 127) { throw ('non-ASCII byte in ' + $file.FullName) } }
    }
}
Invoke-WtTest 'json: ISO-8601 strings stay strings (no DateTime coercion)' { Assert-WtEqual 'String' (ConvertFrom-WtJson '"2026-03-12T15:04:00Z"').GetType().Name }
Invoke-WtTest 'json: empty and single-element arrays survive round trips' { Assert-WtEqual '{"a":[],"b":["x"],"c":[[]],"d":{}}' (ConvertTo-WtCanonicalJson (ConvertFrom-WtJson '{"d":{},"c":[[]],"b":["x"],"a":[]}')) }
Invoke-WtTest 'json: keys are case-sensitive' { Assert-WtEqual 2 (ConvertFrom-WtJson '{"a":1,"A":2}').Count }
Invoke-WtTest 'json: full Int64 range' { Assert-WtEqual '[9223372036854775807,-9223372036854775808,0]' (ConvertTo-WtCanonicalJson (ConvertFrom-WtJson '[9223372036854775807,-9223372036854775808,0]')) }
Invoke-WtTest 'json: surrogate pairs decode' { Assert-WtEqual 2 (ConvertFrom-WtJson '"\ud83d\ude00"').Length }
Invoke-WtTest 'json: control characters escape as \u00xx' { Assert-WtEqual '"\u0001\t"' (ConvertTo-WtCanonicalJson ([string][char]1 + "`t")) }
foreach ($case in @(
        @('float', '{"a":1.5}', 'JSON_FLOAT_FORBIDDEN'), @('exponent', '[1e3]', 'JSON_FLOAT_FORBIDDEN'),
        @('duplicate key', '{"a":1,"a":2}', 'JSON_DUPLICATE_KEY'), @('trailing data', '{} x', 'JSON_TRAILING_DATA'),
        @('lone surrogate', '"\ud800"', 'JSON_LONE_SURROGATE'), @('bad escape', '"\N"', 'JSON_BAD_ESCAPE'),
        @('int overflow', '[9223372036854775808]', 'JSON_INT_RANGE'), @('leading zero', '[01]', 'JSON_EXPECTED_COMMA_OR_BRACKET'),
        @('unterminated', '"abc', 'JSON_UNTERMINATED_STRING'), @('bad literal', 'nul', 'JSON_BAD_LITERAL'),
        @('trailing comma', '[1,]', 'JSON_UNEXPECTED_CHAR'), @('empty input', '', 'JSON_UNEXPECTED_END'))) {
    $label = $case[0]; $text = $case[1]; $code = $case[2]
    Invoke-WtTest ('json rejects ' + $label) { Assert-WtThrowsCode $code { ConvertFrom-WtJson $text } }.GetNewClosure()
}
Invoke-WtTest 'json rejects raw control characters in strings' { Assert-WtThrowsCode 'JSON_CONTROL_CHAR_IN_STRING' { ConvertFrom-WtJson ('"a' + [char]1 + '"') } }
Invoke-WtTest 'json rejects nesting deeper than 64' { Assert-WtThrowsCode 'JSON_TOO_DEEP' { ConvertFrom-WtJson (('[' * 70) + (']' * 70)) } }
Invoke-WtTest 'canonical writer rejects floats and dates' {
    Assert-WtThrowsCode 'JSON_FLOAT_FORBIDDEN' { ConvertTo-WtCanonicalJson @{ a = 1.5 } }
    Assert-WtThrowsCode 'JSON_DATETIME_FORBIDDEN' { ConvertTo-WtCanonicalJson @{ a = [datetime]::UtcNow } }
}
Invoke-WtTest 'canonical hash = sha256(canonical + LF)' { Assert-WtEqual (Get-WtSha256 -Text "{`"a`":1}`n") (Get-WtCanonicalHash (ConvertFrom-WtJson '{"a":1}')) }
Invoke-WtTest 'files: BOM and invalid UTF-8 are rejected' {
    [System.IO.File]::WriteAllBytes((Join-Path $work 'bom.json'), [byte[]](0xEF, 0xBB, 0xBF, 0x7B, 0x7D))
    Assert-WtThrowsCode 'TEXT_BOM_FORBIDDEN' { Read-WtJsonFile -Path (Join-Path $work 'bom.json') }
    [System.IO.File]::WriteAllBytes((Join-Path $work 'bad.json'), [byte[]](0x22, 0xC3, 0x28, 0x22))
    Assert-WtThrowsCode 'TEXT_INVALID_UTF8' { Read-WtJsonFile -Path (Join-Path $work 'bad.json') }
}
Invoke-WtTest 'files: -Canonical requires exact canonical bytes' {
    Set-Content -LiteralPath (Join-Path $work 'pretty.json') -Value '{ "a": 1 }' -NoNewline
    Assert-WtThrowsCode 'JSON_NOT_CANONICAL' { Read-WtJsonFile -Path (Join-Path $work 'pretty.json') -Canonical }
}
Invoke-WtTest 'files: atomic write replaces existing content' {
    $path = Join-Path $work 'atomic.txt'
    Write-WtText -Path $path -Text 'one'
    Write-WtText -Path $path -Text "two`r`n"
    Assert-WtEqual "two`n" (Read-WtText $path)
}
Invoke-WtTest 'time: strict UTC format' {
    Assert-WtEqual '2026-10-13T12:00:00Z' (ConvertTo-WtUtcTime (ConvertFrom-WtUtcTime '2026-10-13T12:00:00Z'))
    Assert-WtThrowsCode 'TIME_FORMAT' { ConvertFrom-WtUtcTime '2026-10-13T12:00:00.123Z' }
    Assert-WtThrowsCode 'TIME_FORMAT' { ConvertFrom-WtUtcTime '2026-02-30T00:00:00Z' }
}

Invoke-WtTest 'json: objects holding "Keys", "Values" or "Count" entries canonicalise every field' {
    $parsed = ConvertFrom-WtJson '{"Keys":["a"],"Values":1,"Count":2,"a":3}'
    Assert-WtEqual '{"Count":2,"Keys":["a"],"Values":1,"a":3}' (ConvertTo-WtCanonicalJson $parsed)
    Assert-WtEqual '{"a":1,"keys":["x"],"values":2}' (ConvertTo-WtCanonicalJson ([ordered]@{ keys = @('x'); values = 2; a = 1 }))
    Assert-WtEqual '{"count":1,"keys":2}' (ConvertTo-WtCanonicalJson @{ keys = 2; count = 1 })
}
# --- paths ---------------------------------------------------------------------------
Invoke-WtTest 'paths: relative path under root' { Assert-WtEqual 'b/c.txt' (Get-WtRelativePath -Root $work -Path (Join-Path $work 'b/c.txt')) }
Invoke-WtTest 'paths: sibling prefix is not "under" root' { Assert-WtThrowsCode 'PATH_NOT_UNDER_ROOT' { Get-WtRelativePath -Root (Join-Path $work 'a') -Path (Join-Path $work 'ab/c') } }
foreach ($case in @(@('a/../b', 'TRAVERSAL_PATH'), @('./a', 'PATH_DOT_SEGMENT'), @('/a', 'PATH_ABSOLUTE'), @('C:/a', 'PATH_ABSOLUTE'), @('a\b', 'PATH_BACKSLASH'), @('a//b', 'PATH_EMPTY_SEGMENT'), @('', 'PATH_EMPTY'))) {
    $path = $case[0]; $code = $case[1]
    Invoke-WtTest ('paths reject "' + $path + '"') { Assert-WtThrowsCode $code { Assert-WtSafeRelativePath $path } }.GetNewClosure()
}
Invoke-WtTest 'paths: hidden files inside a packet are refused' {
    $dir = Join-Path $work 'hidden'
    New-WtDirectory $dir
    Set-Content -LiteralPath (Join-Path $dir '.sneaky') -Value 'x'
    Assert-WtThrowsCode 'PACKET_HIDDEN_FILE_FORBIDDEN' { Get-WtTreeFile $dir }
}

# --- native argv ---------------------------------------------------------------------
Invoke-WtTest 'native: Windows argv quoting (MSVCRT rules, empty argument preserved)' {
    Assert-WtEqual '""' (ConvertTo-WtWindowsArgument '')
    Assert-WtEqual '"a b"' (ConvertTo-WtWindowsArgument 'a b')
    Assert-WtEqual '"a\"b\\"' (ConvertTo-WtWindowsArgument 'a"b\')
    Assert-WtEqual 'C:\plain\path' (ConvertTo-WtWindowsArgument 'C:\plain\path')
}

# --- signatures + trust --------------------------------------------------------------
$key = Join-Path $work 'keys/authority'
$message = Join-Path $work 'message.txt'
Set-Content -LiteralPath $message -Value 'hello' -NoNewline
Invoke-WtTest 'ssh: key generation with an empty passphrase' { New-WtSshKey -Path $key -Comment 'core-tests'; Assert-WtTrue ([System.IO.File]::Exists($key + '.pub')) }
Invoke-WtTest 'ssh: key generation never overwrites' { Assert-WtThrowsCode 'KEY_ALREADY_EXISTS' { New-WtSshKey -Path $key -Comment 'again' } }
Invoke-WtTest 'ssh: signing twice does not prompt or hang' {
    New-WtSignature -KeyPath $key -Namespace 'watchtower' -MessagePath $message -SignaturePath ($message + '.sig')
    New-WtSignature -KeyPath $key -Namespace 'watchtower' -MessagePath $message -SignaturePath ($message + '.sig')
}
$principal = 'single-tenant/watchtower_authority/authority/watchtower'
$bundleText = '{"schema":"neverlost.trust_bundle.v1","created_utc":"2026-10-13T00:00:00Z","principals":[{"principal":"' + $principal + '","keys":[{"key_id":"watchtower-authority-ed25519","alg":"ssh-ed25519","pubkey":"' + (ConvertTo-WtPublicKey (Read-WtText ($key + '.pub'))) + '","namespaces":["watchtower/device-pledge","watchtower","packet/envelope","nfl/ingest-receipt"]}]}]}'
$bundle = ConvertFrom-WtJson $bundleText
Invoke-WtTest 'trust: bundle validates' { Assert-WtTrustBundle $bundle }
Invoke-WtTest 'trust: allowed_signers derived with ordinal-sorted namespaces' {
    $line = (ConvertTo-WtAllowedSigners $bundle).TrimEnd("`n")
    Assert-WtTrue $line.StartsWith($principal + ' namespaces="nfl/ingest-receipt,packet/envelope,watchtower,watchtower/device-pledge" ssh-ed25519 ')
}
Invoke-WtTest 'trust: good signature verifies against the pinned key' {
    Assert-WtTrue (Test-WtTrustedSignature -Bundle $bundle -Principal $principal -KeyId 'watchtower-authority-ed25519' -Namespace 'watchtower' -SignaturePath ($message + '.sig') -MessagePath $message)
}
Invoke-WtTest 'trust: namespace not authorised for the key fails closed' {
    Assert-WtThrowsCode 'SIGNER_NAMESPACE_NOT_AUTHORIZED' { Test-WtTrustedSignature -Bundle $bundle -Principal $principal -KeyId 'watchtower-authority-ed25519' -Namespace 'watchtower/telemetry' -SignaturePath ($message + '.sig') -MessagePath $message }
}
Invoke-WtTest 'trust: unknown principal or key id fails closed' {
    Assert-WtThrowsCode 'SIGNER_NOT_TRUSTED' { Test-WtTrustedSignature -Bundle $bundle -Principal 'stranger' -KeyId 'x' -Namespace 'watchtower' -SignaturePath ($message + '.sig') -MessagePath $message }
    Assert-WtThrowsCode 'SIGNER_NOT_TRUSTED' { Test-WtTrustedSignature -Bundle $bundle -Principal $principal -KeyId 'other' -Namespace 'watchtower' -SignaturePath ($message + '.sig') -MessagePath $message }
}
Invoke-WtTest 'trust: a signature under another namespace does not verify' {
    New-WtSignature -KeyPath $key -Namespace 'packet/envelope' -MessagePath $message -SignaturePath ($message + '.env.sig')
    Assert-WtTrue (-not (Test-WtTrustedSignature -Bundle $bundle -Principal $principal -KeyId 'watchtower-authority-ed25519' -Namespace 'watchtower' -SignaturePath ($message + '.env.sig') -MessagePath $message))
}
Invoke-WtTest 'trust: tampered message does not verify' {
    $tampered = Join-Path $work 'tampered.txt'
    Set-Content -LiteralPath $tampered -Value 'hellx' -NoNewline
    Assert-WtTrue (-not (Test-WtTrustedSignature -Bundle $bundle -Principal $principal -KeyId 'watchtower-authority-ed25519' -Namespace 'watchtower' -SignaturePath ($message + '.sig') -MessagePath $tampered))
}
Invoke-WtTest 'trust: placeholder signature files are rejected' {
    Set-Content -LiteralPath (Join-Path $work 'nosig') -Value 'NOSIGN'
    Assert-WtThrowsCode 'SIG_NOT_ARMORED' { Test-WtTrustedSignature -Bundle $bundle -Principal $principal -KeyId 'watchtower-authority-ed25519' -Namespace 'watchtower' -SignaturePath (Join-Path $work 'nosig') -MessagePath $message }
}
foreach ($case in @(
        @('wrong schema', { param($b) $b['schema'] = 'other' }, 'TRUST_BUNDLE_SCHEMA'),
        @('no principals', { param($b) $b['principals'].Clear() }, 'TRUST_BUNDLE_EMPTY'),
        @('pubkey with comment', { param($b) $b['principals'][0]['keys'][0]['pubkey'] = $b['principals'][0]['keys'][0]['pubkey'] + ' comment' }, 'TRUST_PUBKEY_NOT_CANONICAL'),
        @('namespace with comma', { param($b) $b['principals'][0]['keys'][0]['namespaces'][0] = 'a,b' }, 'TRUST_NAMESPACE_FORMAT'),
        @('duplicate namespace', { param($b) [void]$b['principals'][0]['keys'][0]['namespaces'].Add('watchtower') }, 'TRUST_DUPLICATE_NAMESPACE'),
        @('wrong algorithm', { param($b) $b['principals'][0]['keys'][0]['alg'] = 'ssh-rsa' }, 'TRUST_KEY_ALG'))) {
    $label = $case[0]; $edit = $case[1]; $code = $case[2]
    Invoke-WtTest ('trust rejects bundle: ' + $label) {
        $copy = ConvertFrom-WtJson $bundleText
        & $edit $copy
        Assert-WtThrowsCode $code { Assert-WtTrustBundle $copy }
    }.GetNewClosure()
}

# --- hash chains ---------------------------------------------------------------------
$chainPath = Join-Path $work 'chain.ndjson'
Invoke-WtTest 'chain: append, reopen and verify' {
    $chain = Open-WtHashChain -Path $chainPath
    foreach ($i in 1..3) { $row = New-WtObject; $row['seq'] = $i; [void](Add-WtHashChainEntry -Chain $chain -Row $row) }
    $reopened = Open-WtHashChain -Path $chainPath
    Assert-WtEqual 3 $reopened.Count
    Assert-WtEqual $chain.Head $reopened.Head
    Assert-WtEqual 'GENESIS' ([string]$reopened.Rows[0]['prev_receipt_hash'])
}
$original = Read-WtText $chainPath
foreach ($case in @(
        @('edited value', { param($t) $t.Replace('"seq":2', '"seq":9') }, 'CHAIN_HASH_MISMATCH'),
        @('reordered lines', { param($t) $l = $t.TrimEnd("`n").Split("`n"); ($l[1], $l[0], $l[2] -join "`n") + "`n" }, 'CHAIN_LINK_BROKEN'),
        @('deleted line', { param($t) $l = $t.TrimEnd("`n").Split("`n"); ($l[0], $l[2] -join "`n") + "`n" }, 'CHAIN_LINK_BROKEN'),
        @('CRLF', { param($t) $t.Replace("`n", "`r`n") }, 'CHAIN_CR_FORBIDDEN'),
        @('partial last line', { param($t) $t.TrimEnd("`n") }, 'CHAIN_PARTIAL_LINE'),
        @('non-canonical line', { param($t) $t.Replace('{"prev_receipt_hash"', '{ "prev_receipt_hash"') }, 'CHAIN_LINE_NOT_CANONICAL'))) {
    $label = $case[0]; $edit = $case[1]; $code = $case[2]
    Invoke-WtTest ('chain detects ' + $label) {
        Write-WtBytes -Path $chainPath -Bytes (ConvertTo-WtUtf8 (& $edit $original))
        try { Assert-WtThrowsCode $code { Open-WtHashChain -Path $chainPath } }
        finally { Write-WtBytes -Path $chainPath -Bytes (ConvertTo-WtUtf8 $original) }
    }.GetNewClosure()
}

Invoke-WtTest 'chain: a row holding a "Keys" entry is still hashed over every field' {
    $path = Join-Path $work 'keys-chain.ndjson'
    $chain = Open-WtHashChain -Path $path
    $row = New-WtObject; $row['Keys'] = @('seq'); $row['seq'] = 1; $row['payload'] = 'original'
    [void](Add-WtHashChainEntry -Chain $chain -Row $row)
    Write-WtText -Path $path -Text ((Read-WtText $path).Replace('"payload":"original"', '"payload":"forged"'))
    Assert-WtThrowsCode 'CHAIN_HASH_MISMATCH' { Open-WtHashChain -Path $path }
}

Remove-WtTree $work
Complete-WtTestSuite 'WATCHTOWER_CORE_TESTS'
