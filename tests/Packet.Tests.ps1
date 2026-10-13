# Packet Constitution v1 (Option A): CPR-conformant verification and building.
. (Join-Path $PSScriptRoot 'support/TestHarness.ps1')
$repo = Get-WtRepoRoot
Import-Module (Join-Path $repo 'src/WatchTower/WatchTower.psd1') -Force
foreach ($name in @('Errors', 'IO', 'Json', 'Paths')) { . (Join-Path $repo ('src/WatchTower/Private/{0}.ps1' -f $name)) }
$work = New-WtTempDirectory 'wt_packet_tests'

function New-TestPacket {
    # A valid packet built by WatchTower's own builder.
    param([string]$Name)
    $out = Join-Path $work ('out_' + $Name)
    $manifest = New-WtObject; $manifest['schema'] = 'test.manifest.v1'; $manifest['note'] = $Name
    $payload = New-Object System.Collections.Specialized.OrderedDictionary
    $payload['hello.txt'] = "hello canonical packet runtime`n"
    $payload['nested/data.bin'] = [byte[]](0, 1, 2, 255)
    $built = New-WtPacket -OutputDirectory $out -Manifest $manifest -Payload $payload
    $copy = Join-Path $work $Name
    Copy-WtTree -Source $built.Path -Destination $copy
    return $copy
}

function Set-Sums {
    # Rewrites sha256sums.txt from scratch (isolates faults behind a consistent sums file).
    param([string]$Path)
    [System.IO.File]::Delete((Join-Path $Path 'sha256sums.txt'))
    $builder = New-Object System.Text.StringBuilder
    foreach ($file in (Get-WtTreeFile $Path)) { [void]$builder.Append((Get-WtSha256 -Path (Join-Path $Path $file))).Append('  ').Append($file).Append("`n") }
    Write-WtBytes -Path (Join-Path $Path 'sha256sums.txt') -Bytes (ConvertTo-WtUtf8 $builder.ToString())
}

function Assert-PacketCode {
    param([string]$Path, [string]$Code)
    $result = Test-WtPacket $Path
    Assert-WtEqual $Code $result.Code ('(' + $result.Detail + ')')
    Assert-WtEqual ($Code -ceq 'OK') $result.Valid
}

Invoke-WtTest 'build: produces a valid packet named by its packet_id' {
    $out = Join-Path $work 'build'
    $manifest = New-WtObject; $manifest['schema'] = 'test.manifest.v1'
    $payload = New-Object System.Collections.Specialized.OrderedDictionary; $payload['a.txt'] = 'a'
    $built = New-WtPacket -OutputDirectory $out -Manifest $manifest -Payload $payload
    Assert-WtTrue $built.Created
    Assert-WtEqual $built.PacketId ([System.IO.Path]::GetFileName($built.Path))
    Assert-PacketCode $built.Path 'OK'
    Assert-WtEqual ($built.PacketId + "`n") (Read-WtText (Join-Path $built.Path 'packet_id.txt'))
    Assert-WtEqual $built.PacketId (Get-WtSha256 -Path (Join-Path $built.Path 'manifest.json'))
    $again = New-WtPacket -OutputDirectory $out -Manifest $manifest -Payload $payload
    Assert-WtTrue (-not $again.Created) 'rebuilding identical content must be idempotent'
    Assert-WtEqual 1 @([System.IO.Directory]::GetDirectories($out)).Count 'only the finished packet may be visible in the output directory'
}
Invoke-WtTest 'build: refuses a manifest that carries packet_id' {
    $manifest = New-WtObject; $manifest['Packet_ID'] = 'x'
    Assert-WtThrowsCode 'MANIFEST_CONTAINS_PACKET_ID' { New-WtPacket -OutputDirectory (Join-Path $work 'refuse') -Manifest $manifest -Payload @{ 'a' = 'b' } }
}
Invoke-WtTest 'build: a signer callback that writes only under signatures/ succeeds and is covered by the sums' {
    $manifest = New-WtObject; $manifest['schema'] = 't'
    $built = New-WtPacket -OutputDirectory (Join-Path $work 'goodsigner') -Manifest $manifest -Payload @{ 'a' = 'b' } -SignatureContext 'ctx' -Signatures {
        param($Build, $PacketId, $Context)
        Write-WtText -Path (Join-Path $Build 'signatures/detached.sig') -Text ($PacketId + ' ' + $Context)
    }
    Assert-PacketCode $built.Path 'OK'
    Assert-WtTrue ((Read-WtText (Join-Path $built.Path 'sha256sums.txt')).Contains('  signatures/detached.sig')) 'signature not covered'
    Assert-WtEqual ($built.PacketId + ' ctx' + "`n") (Read-WtText (Join-Path $built.Path 'signatures/detached.sig'))
}
Invoke-WtTest 'build: signer callback may only write under signatures/' {
    $manifest = New-WtObject; $manifest['schema'] = 't'
    Assert-WtThrowsCode 'PACKET_SIGNER_WROTE_OUTSIDE_SIGNATURES' {
        New-WtPacket -OutputDirectory (Join-Path $work 'badsigner') -Manifest $manifest -Payload @{ 'a' = 'b' } -Signatures { param($Build) Set-Content -LiteralPath (Join-Path $Build 'payload/injected.txt') -Value 'x' }
    }
}
Invoke-WtTest 'verify: never modifies the packet' {
    $packet = New-TestPacket 'nonmutation'
    $before = Get-WtTreeDigest $packet
    [void](Test-WtPacket $packet)
    Assert-WtEqual $before (Get-WtTreeDigest $packet)
}

# Every CPR failure code, plus WatchTower's stricter rules. Each case isolates one fault.
$cases = @(
    @('missing directory', { param($p) [System.IO.Directory]::Delete($p, $true) }, 'PACKET_DIR_MISSING'),
    @('missing manifest', { param($p) [System.IO.File]::Delete((Join-Path $p 'manifest.json')) }, 'MISSING_MANIFEST'),
    @('missing packet_id.txt', { param($p) [System.IO.File]::Delete((Join-Path $p 'packet_id.txt')) }, 'MISSING_PACKET_ID'),
    @('missing sha256sums.txt', { param($p) [System.IO.File]::Delete((Join-Path $p 'sha256sums.txt')) }, 'MISSING_SHA256SUMS'),
    @('manifest contains packet_id (any case)', { param($p)
            $m = Read-WtJsonFile -Path (Join-Path $p 'manifest.json'); $m['PACKET_ID'] = 'x'; Write-WtJsonFile -Path (Join-Path $p 'manifest.json') -Value $m
            Write-WtText -Path (Join-Path $p 'packet_id.txt') -Text (Get-WtSha256 -Path (Join-Path $p 'manifest.json')); Set-Sums $p }, 'MANIFEST_CONTAINS_PACKET_ID'),
    @('manifest is not strict JSON', { param($p) Write-WtBytes -Path (Join-Path $p 'manifest.json') -Bytes (ConvertTo-WtUtf8 '{"a":1,"a":2}'); Set-Sums $p }, 'MANIFEST_INVALID'),
    @('packet_id.txt uppercase', { param($p) Write-WtBytes -Path (Join-Path $p 'packet_id.txt') -Bytes (ConvertTo-WtUtf8 ((Get-WtSha256 -Path (Join-Path $p 'manifest.json')).ToUpperInvariant() + "`n")); Set-Sums $p }, 'BAD_PACKET_ID_FORMAT'),
    @('packet_id.txt with CRLF', { param($p) Write-WtBytes -Path (Join-Path $p 'packet_id.txt') -Bytes (ConvertTo-WtUtf8 ((Get-WtSha256 -Path (Join-Path $p 'manifest.json')) + "`r`n")); Set-Sums $p }, 'BAD_PACKET_ID_FORMAT'),
    @('packet_id mismatch', { param($p) Write-WtBytes -Path (Join-Path $p 'packet_id.txt') -Bytes (ConvertTo-WtUtf8 (('0' * 64) + "`n")); Set-Sums $p }, 'PACKET_ID_MISMATCH'),
    @('manifest edited after id', { param($p) Write-WtBytes -Path (Join-Path $p 'manifest.json') -Bytes (ConvertTo-WtUtf8 "{`"schema`":`"tampered`"}`n"); Set-Sums $p }, 'PACKET_ID_MISMATCH'),
    @('empty sha256sums', { param($p) Write-WtBytes -Path (Join-Path $p 'sha256sums.txt') -Bytes ([byte[]]@()) }, 'EMPTY_SHA256SUMS'),
    @('sums line with one space', { param($p) $t = Read-WtText (Join-Path $p 'sha256sums.txt'); Write-WtBytes -Path (Join-Path $p 'sha256sums.txt') -Bytes (ConvertTo-WtUtf8 ($t -replace '  ', ' ')) }, 'BAD_SHA256SUM_LINE'),
    @('sums uppercase hex', { param($p) $t = Read-WtText (Join-Path $p 'sha256sums.txt'); Write-WtBytes -Path (Join-Path $p 'sha256sums.txt') -Bytes (ConvertTo-WtUtf8 $t.ToUpperInvariant().Replace('MANIFEST.JSON', 'manifest.json')) }, 'BAD_SHA256SUM_LINE'),
    @('sums with CRLF', { param($p) $t = Read-WtText (Join-Path $p 'sha256sums.txt'); Write-WtBytes -Path (Join-Path $p 'sha256sums.txt') -Bytes (ConvertTo-WtUtf8 $t.Replace("`n", "`r`n")) }, 'SHA256SUMS_CR_FORBIDDEN'),
    @('traversal path', { param($p) Add-Content -LiteralPath (Join-Path $p 'sha256sums.txt') -Value (('a' * 64) + '  ../outside.txt') -NoNewline; Add-Content -LiteralPath (Join-Path $p 'sha256sums.txt') -Value "`n" -NoNewline }, 'TRAVERSAL_PATH'),
    @('absolute path', { param($p) $t = Read-WtText (Join-Path $p 'sha256sums.txt'); Write-WtBytes -Path (Join-Path $p 'sha256sums.txt') -Bytes (ConvertTo-WtUtf8 ($t + ('a' * 64) + "  /etc/passwd`n")) }, 'PATH_ABSOLUTE'),
    @('sums lists itself', { param($p) $t = Read-WtText (Join-Path $p 'sha256sums.txt'); Write-WtBytes -Path (Join-Path $p 'sha256sums.txt') -Bytes (ConvertTo-WtUtf8 ($t + ('a' * 64) + "  sha256sums.txt`n")) }, 'SHA256SUMS_SELF_INCLUDED'),
    @('duplicate sums entry', { param($p) $t = Read-WtText (Join-Path $p 'sha256sums.txt'); $first = $t.Split("`n")[0]; Write-WtBytes -Path (Join-Path $p 'sha256sums.txt') -Bytes (ConvertTo-WtUtf8 ($t + $first + "`n")) }, 'SHA256SUMS_DUPLICATE_ENTRY'),
    @('listed file missing', { param($p) [System.IO.File]::Delete((Join-Path $p 'payload/hello.txt')) }, 'MISSING_TARGET'),
    @('payload tampered', { param($p) Write-WtBytes -Path (Join-Path $p 'payload/hello.txt') -Bytes (ConvertTo-WtUtf8 "tampered payload`n") }, 'SHA256_MISMATCH'),
    @('unlisted extra file', { param($p) Write-WtText -Path (Join-Path $p 'payload/extra.txt') -Text 'x' }, 'SHA256SUMS_MISSING_COVERAGE'),
    @('hidden file', { param($p) Write-WtText -Path (Join-Path $p 'payload/.hidden') -Text 'x' }, 'PACKET_HIDDEN_FILE_FORBIDDEN')
)
foreach ($case in $cases) {
    $label = $case[0]; $mutate = $case[1]; $code = $case[2]
    Invoke-WtTest ('verify rejects: ' + $label + ' -> ' + $code) {
        $packet = New-TestPacket ('case_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        & $mutate $packet
        Assert-PacketCode $packet $code
    }
}

Invoke-WtTest 'verify rejects symbolic links (where the OS allows creating them)' {
    $packet = New-TestPacket 'symlink'
    $link = Join-Path $packet 'payload/link.txt'
    try { [void](New-Item -ItemType SymbolicLink -Path $link -Target (Join-Path $packet 'payload/hello.txt') -ErrorAction Stop) }
    catch { Write-Host 'CASE_NOTE: symbolic links not permitted for this user; covered on Linux CI'; return }
    Assert-PacketCode $packet 'PACKET_SYMLINK_FORBIDDEN'
}

Invoke-WtTest 'verify accepts CPR''s own minimal vector layout (LF manifest, hex+LF id)' {
    $packet = Join-Path $work 'cpr_layout'
    New-WtDirectory (Join-Path $packet 'payload')
    Write-WtBytes -Path (Join-Path $packet 'payload/hello.txt') -Bytes (ConvertTo-WtUtf8 "hello canonical packet runtime`n")
    Write-WtBytes -Path (Join-Path $packet 'manifest.json') -Bytes (ConvertTo-WtUtf8 "{`"schema`":`"cpr.packet.manifest.v1`",`"constitution`":`"packet_constitution_v1_option_a`"}`n")
    Write-WtBytes -Path (Join-Path $packet 'packet_id.txt') -Bytes (ConvertTo-WtUtf8 ((Get-WtSha256 -Path (Join-Path $packet 'manifest.json')) + "`n"))
    Set-Sums $packet
    Assert-PacketCode $packet 'OK'
}

Invoke-WtTest 'verify rejects: packet_id smuggled behind a "Keys" entry (PowerShell dictionary member access)' {
    $path = New-TestPacket 'keys-smuggle'
    Write-WtText -Path (Join-Path $path 'manifest.json') -Text '{"Keys":[],"packet_id":"x","schema":"t"}'
    Write-WtText -Path (Join-Path $path 'packet_id.txt') -Text (Get-WtSha256 -Path (Join-Path $path 'manifest.json'))
    Set-Sums $path
    Assert-PacketCode $path 'MANIFEST_CONTAINS_PACKET_ID'
}

Remove-WtTree $work
Complete-WtTestSuite 'WATCHTOWER_PACKET_TESTS'
