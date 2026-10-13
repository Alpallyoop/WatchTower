# Path handling that behaves identically on Windows and Linux, on .NET
# Framework (PowerShell 5.1) and .NET (PowerShell 7).
# (CPR's and the legacy WatchTower verifiers built relative paths through
# System.Uri with a hard-coded '\' and crash on Linux; this does not.)

function Get-WtRelativePath {
    # Root-relative path with '/' separators; fails if $Path is outside $Root.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Path)
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $rootFull = (Resolve-WtFullPath $Root).TrimEnd([char[]]@('\', '/'))
    $full = Resolve-WtFullPath $Path
    $prefix = $rootFull + $separator
    $comparison = [StringComparison]::Ordinal
    if (Test-WtWindows) { $comparison = [StringComparison]::OrdinalIgnoreCase }
    if (-not $full.StartsWith($prefix, $comparison)) { throw (New-WtFailure 'PATH_NOT_UNDER_ROOT' $full) }
    $relative = $full.Substring($prefix.Length)
    if (Test-WtWindows) { $relative = $relative.Replace('\', '/') }
    return $relative
}

function Assert-WtSafeRelativePath {
    # CPR Test-SafeRelativePath rules, plus (stricter) no '.' segments,
    # no backslashes and no control characters.
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { throw (New-WtFailure 'PATH_EMPTY') }
    if ($Path.StartsWith('/') -or $Path.StartsWith('\') -or $Path -match '^[A-Za-z]:') { throw (New-WtFailure 'PATH_ABSOLUTE' $Path) }
    if ($Path.Contains('\')) { throw (New-WtFailure 'PATH_BACKSLASH' $Path) }
    foreach ($ch in $Path.ToCharArray()) { if ([int]$ch -lt 32) { throw (New-WtFailure 'PATH_CONTROL_CHAR' $Path) } }
    foreach ($segment in $Path.Split('/')) {
        if ($segment.Length -eq 0) { throw (New-WtFailure 'PATH_EMPTY_SEGMENT' $Path) }
        if ($segment -eq '..') { throw (New-WtFailure 'TRAVERSAL_PATH' $Path) }
        if ($segment -eq '.') { throw (New-WtFailure 'PATH_DOT_SEGMENT' $Path) }
    }
}

function Get-WtTreeFile {
    # Every file under $Root as ordinal-sorted '/'-relative paths. Fails closed
    # on symbolic links / reparse points and on hidden files or folders, so a
    # packet can never smuggle content past sha256sums coverage.
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootFull = Resolve-WtFullPath $Root
    if (-not [System.IO.Directory]::Exists($rootFull)) { throw (New-WtFailure 'PACKET_DIR_MISSING' $rootFull) }
    $files = New-Object System.Collections.Generic.List[string]
    foreach ($item in @(Get-ChildItem -LiteralPath $rootFull -Recurse -Force -ErrorAction Stop)) {
        $attributes = $item.Attributes
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw (New-WtFailure 'PACKET_SYMLINK_FORBIDDEN' $item.FullName) }
        if ($item.Name.StartsWith('.') -or (($attributes -band [System.IO.FileAttributes]::Hidden) -ne 0)) { throw (New-WtFailure 'PACKET_HIDDEN_FILE_FORBIDDEN' $item.FullName) }
        # Only regular files and directories: reading a named pipe, socket or device would
        # block or never end (Unix; on Windows the file system cannot hold them).
        if (-not (Test-WtWindows)) {
            $stat = $null
            if ($null -ne $item.PSObject.Properties['UnixStat']) { $stat = $item.UnixStat }
            if ($null -eq $stat) { throw (New-WtFailure 'PACKET_FILE_TYPE_UNKNOWN' $item.FullName) }
            if (@('File', 'Directory') -cnotcontains [string]$stat.ItemType) { throw (New-WtFailure 'PACKET_SPECIAL_FILE_FORBIDDEN' $item.FullName) }
        }
        if (-not $item.PSIsContainer) { $files.Add((Get-WtRelativePath -Root $rootFull -Path $item.FullName)) }
    }
    $sorted = $files.ToArray()
    [Array]::Sort($sorted, [System.StringComparer]::Ordinal)
    return , $sorted
}

function ConvertTo-WtPathSegment {
    # A directory name for an untrusted identifier (for example a producer's device_id)
    # that is safe and unambiguous on Windows and Unix. Plain lowercase identifiers are
    # used as-is; anything else (':' alternate-data-stream syntax, trailing dots that
    # Windows strips, case variants that collide on NTFS, reserved names such as NUL)
    # becomes 'id-' + the first 40 hex digits of its SHA-256. Deterministic.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $reserved = '^(?i:con|prn|aux|nul|com[0-9]|lpt[0-9])$'
    if ($Value -cmatch '^[a-z0-9][a-z0-9_-]{0,63}$' -and $Value -notmatch $reserved) { return $Value }
    return 'id-' + (Get-WtSha256 -Text $Value).Substring(0, 40)
}

function New-WtTempDirectory {
    [OutputType([string])]
    param([string]$Prefix = 'watchtower')
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ('{0}_{1}' -f $Prefix, [guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($path)
    return $path
}

function Remove-WtTree {
    param([AllowEmptyString()][string]$Path)
    if ($Path -and [System.IO.Directory]::Exists($Path)) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue }
}

function Copy-WtTree {
    # Byte-exact recursive copy of a directory into a new destination.
    param([Parameter(Mandatory = $true)][string]$Source, [Parameter(Mandatory = $true)][string]$Destination)
    if ([System.IO.Directory]::Exists($Destination)) { throw (New-WtFailure 'DESTINATION_EXISTS' $Destination) }
    New-WtDirectory $Destination
    foreach ($relative in (Get-WtTreeFile $Source)) {
        $target = Join-Path $Destination $relative
        New-WtDirectory ([System.IO.Path]::GetDirectoryName($target))
        [System.IO.File]::Copy((Join-Path $Source $relative), $target)
    }
}
