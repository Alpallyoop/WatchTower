# Deterministic file IO: UTF-8 without BOM, LF only, atomic replace, durable append.

$script:WtUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
$script:WtInvariant = [System.Globalization.CultureInfo]::InvariantCulture

function Test-WtWindows {
    [OutputType([bool])]
    param()
    return ([System.IO.Path]::DirectorySeparatorChar -eq '\')
}

function Resolve-WtFullPath {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path)
}

function New-WtDirectory {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return }
    if (-not [System.IO.Directory]::Exists($Path)) { [void][System.IO.Directory]::CreateDirectory($Path) }
}

function Read-WtBytes {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not [System.IO.File]::Exists($Path)) { throw (New-WtFailure 'FILE_MISSING' $Path) }
    return , ([System.IO.File]::ReadAllBytes($Path))
}

function ConvertFrom-WtUtf8 {
    # Strict decode: no BOM, valid UTF-8 only.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [string]$Source = 'text')
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        throw (New-WtFailure 'TEXT_BOM_FORBIDDEN' $Source)
    }
    try { return $script:WtUtf8.GetString($Bytes) }
    catch { throw (New-WtFailure 'TEXT_INVALID_UTF8' $Source) }
}

function ConvertTo-WtUtf8 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    return , ($script:WtUtf8.GetBytes($Text))
}

function Read-WtText {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)
    return ConvertFrom-WtUtf8 -Bytes (Read-WtBytes $Path) -Source $Path
}

function Write-WtBytes {
    # Atomic: temp file in the same directory, flushed to disk, then replaced.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $full = Resolve-WtFullPath $Path
    New-WtDirectory ([System.IO.Path]::GetDirectoryName($full))
    $temp = '{0}.tmp-{1}-{2}' -f $full, [System.Diagnostics.Process]::GetCurrentProcess().Id, [guid]::NewGuid().ToString('N').Substring(0, 8)
    $stream = New-Object System.IO.FileStream($temp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    # [NullString]::Value: PowerShell would otherwise pass $null as "" (invalid backup path).
    if ([System.IO.File]::Exists($full)) { [System.IO.File]::Replace($temp, $full, [System.Management.Automation.Language.NullString]::Value) }
    else { [System.IO.File]::Move($temp, $full) }
}

function Write-WtText {
    # UTF-8 no BOM, CR/CRLF normalised to LF, exactly one trailing LF.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $normalised = ($Text -replace "`r`n", "`n") -replace "`r", "`n"
    if (-not $normalised.EndsWith("`n")) { $normalised = $normalised + "`n" }
    Write-WtBytes -Path $Path -Bytes (ConvertTo-WtUtf8 $normalised)
}

function Add-WtLine {
    # Durable append of one LF-terminated line (exclusive writer, flushed to disk).
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Line)
    if ($Line.Contains("`n") -or $Line.Contains("`r")) { throw (New-WtFailure 'APPEND_LINE_HAS_NEWLINE' $Path) }
    $full = Resolve-WtFullPath $Path
    New-WtDirectory ([System.IO.Path]::GetDirectoryName($full))
    $bytes = ConvertTo-WtUtf8 ($Line + "`n")
    $stream = New-Object System.IO.FileStream($full, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Get-WtSha256 {
    # Lowercase hex SHA-256 of bytes, a file's exact bytes, or UTF-8 text.
    [CmdletBinding(DefaultParameterSetName = 'Bytes')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Bytes')][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')][string]$Path,
        [Parameter(Mandatory = $true, ParameterSetName = 'Text')][AllowEmptyString()][string]$Text
    )
    if ($PSCmdlet.ParameterSetName -eq 'Path') { $Bytes = Read-WtBytes $Path }
    elseif ($PSCmdlet.ParameterSetName -eq 'Text') { $Bytes = ConvertTo-WtUtf8 $Text }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

function Test-WtHex64 {
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    return ($null -ne $Value -and $Value -cmatch '^[0-9a-f]{64}$')
}

function Get-WtUtcNow {
    [OutputType([string])]
    param()
    return [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $script:WtInvariant)
}

function ConvertFrom-WtUtcTime {
    # Strict second-precision UTC: YYYY-MM-DDTHH:MM:SSZ
    [OutputType([datetime])]
    param([AllowNull()][AllowEmptyString()][string]$Value, [string]$Field = 'time')
    if ($null -eq $Value -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') {
        throw (New-WtFailure 'TIME_FORMAT' ('{0}={1}' -f $Field, $Value))
    }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $parsed = [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact($Value, "yyyy-MM-dd'T'HH:mm:ss'Z'", $script:WtInvariant, $styles, [ref]$parsed)) {
        throw (New-WtFailure 'TIME_FORMAT' ('{0}={1}' -f $Field, $Value))
    }
    return $parsed
}

function ConvertTo-WtUtcTime {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][datetime]$Value)
    return $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $script:WtInvariant)
}
