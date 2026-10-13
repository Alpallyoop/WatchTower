function Test-WtPacket {
    <#
    .SYNOPSIS
        Verifies a Packet Constitution v1 (Option A) directory packet without modifying it.
    .DESCRIPTION
        Conforms to CPR (the Canonical Packet Runtime) check-for-check and uses CPR's failure
        codes, so a packet NFL will witness is one WatchTower accepts and vice versa. WatchTower
        is stricter in five places, each to close a gap rather than to differ:
          - packet_id.txt must be exactly 64 lowercase hex + LF (no BOM, CRLF or uppercase);
          - sha256sums.txt must be UTF-8 without BOM, LF only, lowercase hex, no duplicate paths;
          - manifest.json must be strict JSON (no duplicate keys, no floats);
          - hidden files and symbolic links anywhere in the packet are rejected;
          - '.' segments and backslashes in listed paths are rejected.
        Signatures are not part of PCv1 (CPR checks none); see Test-WtTelemetryPacket.
    .OUTPUTS
        PSCustomObject: Valid, Code, Detail, PacketId, Files
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true, Position = 0)][string]$Path)

    $result = [pscustomobject]@{ Valid = $false; Code = ''; Detail = ''; PacketId = ''; Files = @() }
    try {
        $root = Resolve-WtFullPath $Path
        if ([System.IO.Directory]::Exists($root) -and (([System.IO.DirectoryInfo]$root).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw (New-WtFailure 'PACKET_SYMLINK_FORBIDDEN' 'packet root')
        }
        $tree = Get-WtTreeFile $root
        $present = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($file in $tree) { [void]$present.Add($file) }
        foreach ($required in @(@('manifest.json', 'MISSING_MANIFEST'), @('packet_id.txt', 'MISSING_PACKET_ID'), @('sha256sums.txt', 'MISSING_SHA256SUMS'))) {
            if (-not $present.Contains($required[0])) { throw (New-WtFailure $required[1]) }
        }

        $manifestPath = Join-Path $root 'manifest.json'
        $manifestBytes = Read-WtBytes $manifestPath
        try { $manifest = ConvertFrom-WtJson (ConvertFrom-WtUtf8 -Bytes $manifestBytes -Source 'manifest.json') }
        catch { throw (New-WtFailure 'MANIFEST_INVALID' (Get-WtFailureCode $_)) }
        if (-not ($manifest -is [System.Collections.IDictionary])) { throw (New-WtFailure 'MANIFEST_INVALID' 'JSON_NOT_OBJECT') }
        foreach ($key in $manifest.PSBase.Keys) {
            if ([string]::Equals([string]$key, 'packet_id', [StringComparison]::OrdinalIgnoreCase)) { throw (New-WtFailure 'MANIFEST_CONTAINS_PACKET_ID') }
        }

        $idText = ConvertFrom-WtUtf8 -Bytes (Read-WtBytes (Join-Path $root 'packet_id.txt')) -Source 'packet_id.txt'
        if ($idText -cnotmatch '^[0-9a-f]{64}\n$') { throw (New-WtFailure 'BAD_PACKET_ID_FORMAT') }
        $packetId = $idText.Substring(0, 64)
        if ((Get-WtSha256 -Bytes $manifestBytes) -cne $packetId) { throw (New-WtFailure 'PACKET_ID_MISMATCH') }

        $sumsText = ConvertFrom-WtUtf8 -Bytes (Read-WtBytes (Join-Path $root 'sha256sums.txt')) -Source 'sha256sums.txt'
        if ($sumsText.Contains("`r")) { throw (New-WtFailure 'SHA256SUMS_CR_FORBIDDEN') }
        if ($sumsText.Length -eq 0) { throw (New-WtFailure 'EMPTY_SHA256SUMS') }
        if (-not $sumsText.EndsWith("`n")) { throw (New-WtFailure 'BAD_SHA256SUM_LINE' 'missing final LF') }
        $listed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($line in $sumsText.Substring(0, $sumsText.Length - 1).Split("`n")) {
            $match = [regex]::Match($line, '^([0-9a-f]{64})  (.+)$')
            if (-not $match.Success) { throw (New-WtFailure 'BAD_SHA256SUM_LINE' $line) }
            $relative = $match.Groups[2].Value
            Assert-WtSafeRelativePath $relative
            if ($relative -ceq 'sha256sums.txt') { throw (New-WtFailure 'SHA256SUMS_SELF_INCLUDED') }
            if (-not $listed.Add($relative)) { throw (New-WtFailure 'SHA256SUMS_DUPLICATE_ENTRY' $relative) }
            if (-not $present.Contains($relative)) { throw (New-WtFailure 'MISSING_TARGET' $relative) }
            if ((Get-WtSha256 -Path (Join-Path $root $relative)) -cne $match.Groups[1].Value) { throw (New-WtFailure 'SHA256_MISMATCH' $relative) }
        }
        foreach ($file in $tree) {
            if ($file -ceq 'sha256sums.txt') { continue }
            if (-not $listed.Contains($file)) { throw (New-WtFailure 'SHA256SUMS_MISSING_COVERAGE' $file) }
        }

        $result.Valid = $true
        $result.Code = 'OK'
        $result.PacketId = $packetId
        $result.Files = $tree
    }
    catch {
        $result.Code = Get-WtFailureCode $_
        $result.Detail = Get-WtFailureMessage $_
    }
    return $result
}

function New-WtPacket {
    <#
    .SYNOPSIS
        Builds a PCv1 Option A packet that CPR accepts, signs it, verifies it, and publishes it
        atomically as <OutputDirectory>/<packet_id>.
    .DESCRIPTION
        Order (CPR build + Receipt Artifact v1): payload -> manifest.json -> packet_id.txt ->
        signatures -> sha256sums.txt (last, covering every other file). The manifest is canonical
        JSON + LF and never contains packet_id. The packet is verified with Test-WtPacket before
        it becomes visible; an identical existing packet is returned unchanged (idempotent).
    .PARAMETER Payload
        Ordered map of payload-relative path -> string (written as UTF-8) or byte[].
    .PARAMETER Signatures
        Scriptblock invoked as & $Signatures <buildDirectory> <packetId> <SignatureContext> after
        packet_id.txt is written and before sha256sums.txt; it may only add files under
        signatures/. Context is passed explicitly (no reliance on dynamic scoping).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Manifest,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Payload,
        [scriptblock]$Signatures,
        [AllowNull()]$SignatureContext
    )
    foreach ($key in $Manifest.PSBase.Keys) {
        if ([string]::Equals([string]$key, 'packet_id', [StringComparison]::OrdinalIgnoreCase)) { throw (New-WtFailure 'MANIFEST_CONTAINS_PACKET_ID') }
    }
    New-WtDirectory $OutputDirectory
    # Build next to (not inside) the output directory: consumers such as NFL poll the
    # output directory, so only complete, verified packets may ever appear there. The
    # sibling keeps the final rename atomic (same volume).
    $outputFull = (Resolve-WtFullPath $OutputDirectory).TrimEnd([char[]]@('\', '/'))
    $staging = Join-Path ([System.IO.Path]::GetDirectoryName($outputFull)) '_staging'
    $build = Join-Path $staging ('build_' + [guid]::NewGuid().ToString('N'))
    New-WtDirectory $build
    try {
        foreach ($relative in $Payload.PSBase.Keys) {
            $path = 'payload/' + [string]$relative
            Assert-WtSafeRelativePath $path
            $content = $Payload[$relative]
            if ($content -is [byte[]]) { $bytes = [byte[]]$content } else { $bytes = ConvertTo-WtUtf8 ([string]$content) }
            Write-WtBytes -Path (Join-Path $build $path) -Bytes $bytes
        }
        Write-WtJsonFile -Path (Join-Path $build 'manifest.json') -Value $Manifest
        $packetId = Get-WtSha256 -Path (Join-Path $build 'manifest.json')
        Write-WtBytes -Path (Join-Path $build 'packet_id.txt') -Bytes (ConvertTo-WtUtf8 ($packetId + "`n"))

        if ($Signatures) {
            # Get-WtTreeFile already returns string[]; wrapping it in @() would nest it.
            $before = Get-WtTreeFile $build
            & $Signatures $build $packetId $SignatureContext
            foreach ($file in (Get-WtTreeFile $build)) {
                if ($before -cnotcontains $file -and -not $file.StartsWith('signatures/')) { throw (New-WtFailure 'PACKET_SIGNER_WROTE_OUTSIDE_SIGNATURES' $file) }
            }
        }

        $sums = New-Object System.Text.StringBuilder
        foreach ($file in (Get-WtTreeFile $build)) {
            [void]$sums.Append((Get-WtSha256 -Path (Join-Path $build $file))).Append('  ').Append($file).Append("`n")
        }
        Write-WtBytes -Path (Join-Path $build 'sha256sums.txt') -Bytes (ConvertTo-WtUtf8 $sums.ToString())

        $check = Test-WtPacket $build
        if (-not $check.Valid) { throw (New-WtFailure 'PACKET_BUILD_SELF_VERIFY_FAILED' $check.Code) }

        $final = Join-Path $outputFull $packetId
        if ([System.IO.Directory]::Exists($final)) {
            $existing = Test-WtPacket $final
            $same = $existing.Valid -and ((Get-WtSha256 -Path (Join-Path $final 'sha256sums.txt')) -ceq (Get-WtSha256 -Path (Join-Path $build 'sha256sums.txt')))
            if (-not $same) { throw (New-WtFailure 'PACKET_EXISTS_DIFFERENT' $packetId) }
            return [pscustomobject]@{ PacketId = $packetId; Path = $final; Created = $false }
        }
        [System.IO.Directory]::Move($build, $final)
        return [pscustomobject]@{ PacketId = $packetId; Path = $final; Created = $true }
    }
    finally { Remove-WtTree $build }
}
