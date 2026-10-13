# Proposal 0004 — CPR: relative paths on Linux and macOS

| | |
|---|---|
| Status | Proposed to the CPR owner |
| Date | 2026-10-13 |
| Evidence | `tests/Interop.Tests.ps1` (`Invoke-Cpr`) |

CPR's `scripts/_lib_cpr_v1.ps1` computes packet-relative paths with `Get-RelativePathNormalized`
(line 63), which marks the base as a directory by appending `\` and then uses
`Uri.MakeRelativeUri`. On Windows this works. On Linux and macOS `\` is an ordinary file-name
character, so the base is not treated as a directory, the relative paths come out wrong, and
`verify_packet_v1.ps1` fails every packet there, including valid ones.

WatchTower's interop suite works around it only in a temporary copy of CPR, by replacing that one
helper with an equivalent based on `[System.IO.Path]::GetRelativePath`; every packet rule runs
unmodified. The CPR checkout is never written.

## Proposed change (CPR)

```powershell
function Get-RelativePathNormalized([string]$BasePath, [string]$TargetPath) {
    $base = [System.IO.Path]::GetFullPath($BasePath).TrimEnd([char[]]@('\', '/'))
    $target = [System.IO.Path]::GetFullPath($TargetPath)
    if (-not $target.StartsWith($base + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::Ordinal)) {
        throw 'PATH_NOT_UNDER_ROOT'
    }
    return $target.Substring($base.Length + 1).Replace('\', '/')
}
```

This works on Windows PowerShell 5.1 (no `GetRelativePath` there) and on PowerShell 7 everywhere.
Once CPR ships it, the interop suite's substitution can be removed.
