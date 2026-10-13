# Minimal, dependency-free test harness (runs offline on PowerShell 5.1 and 7).
# Each suite prints CASE_OK / CASE_FAIL lines and ends with <SUITE>_OK or <SUITE>_FAIL.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WtTestPassed = 0
$script:WtTestFailed = New-Object System.Collections.ArrayList
$script:WtTestSkipped = New-Object System.Collections.ArrayList

function Invoke-WtTest {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][scriptblock]$Body)
    try {
        [void](& $Body)
        $script:WtTestPassed++
        Write-Host ('CASE_OK: ' + $Name)
    }
    catch {
        if ($_.Exception.Data.Contains('wt_skip')) {
            [void]$script:WtTestSkipped.Add(('{0} ({1})' -f $Name, $_.Exception.Data['wt_skip']))
            Write-Host ('CASE_SKIP: {0} :: {1}' -f $Name, $_.Exception.Data['wt_skip'])
            return
        }
        [void]$script:WtTestFailed.Add($Name)
        Write-Host ('CASE_FAIL: {0} :: {1}' -f $Name, $_.Exception.Message)
    }
}

function Skip-WtTest {
    # Marks the current case as skipped because an optional dependency is unavailable.
    # A skip is reported as such (CASE_SKIP / skipped=N) and is never counted as a pass.
    param([Parameter(Mandatory = $true)][string]$Reason)
    $exception = New-Object System.InvalidOperationException('SKIP: ' + $Reason)
    $exception.Data['wt_skip'] = $Reason
    throw $exception
}

function Assert-WtEqual {
    param([AllowNull()]$Expected, [AllowNull()]$Actual, [string]$Because = '')
    if (-not [object]::Equals($Expected, $Actual) -and -not ($Expected -is [string] -and $Actual -is [string] -and [string]::Equals($Expected, $Actual, [StringComparison]::Ordinal))) {
        throw ('expected [{0}] but got [{1}] {2}' -f $Expected, $Actual, $Because)
    }
}

function Assert-WtTrue {
    param([bool]$Condition, [string]$Because = 'condition was false')
    if (-not $Condition) { throw $Because }
}

function Assert-WtThrowsCode {
    # The script block must throw a WT_FAIL with exactly this code.
    param([Parameter(Mandatory = $true)][string]$Code, [Parameter(Mandatory = $true)][scriptblock]$Body)
    try { [void](& $Body) }
    catch {
        $actual = ''
        $match = [regex]::Match($_.Exception.Message, 'WT_FAIL:([A-Z0-9_]+)')
        if ($match.Success) { $actual = $match.Groups[1].Value }
        if ($actual -cne $Code) { throw ('expected failure {0} but got {1} ({2})' -f $Code, $actual, $_.Exception.Message) }
        return
    }
    throw ('expected failure {0} but nothing was thrown' -f $Code)
}

function Complete-WtTestSuite {
    param([Parameter(Mandatory = $true)][string]$Suite)
    $skipped = $script:WtTestSkipped.Count
    if ($script:WtTestFailed.Count -gt 0) {
        Write-Host ('{0}_FAIL passed={1} failed={2} skipped={3} [{4}]' -f $Suite, $script:WtTestPassed, $script:WtTestFailed.Count, $skipped, ($script:WtTestFailed -join '; '))
        exit 1
    }
    if ($skipped -gt 0) {
        Write-Host ('{0}_OK cases={1} skipped={2} [{3}]' -f $Suite, $script:WtTestPassed, $skipped, ($script:WtTestSkipped -join '; '))
        exit 0
    }
    Write-Host ('{0}_OK cases={1}' -f $Suite, $script:WtTestPassed)
    exit 0
}

function Get-WtRepoRoot {
    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
}

function Get-WtTreeDigest {
    # Digest of every file's relative path and bytes, to prove non-mutation.
    param([Parameter(Mandatory = $true)][string]$Path)
    $root = (Resolve-Path -LiteralPath $Path).Path
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -Force -File)) {
        $relative = $file.FullName.Substring($root.Length).TrimStart([char[]]@('\', '/')).Replace('\', '/')
        $digest = ([System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes($file.FullName))) -replace '-', '').ToLowerInvariant()
        $lines.Add($relative + "`t" + $digest)
    }
    $sha.Dispose()
    $sorted = $lines.ToArray()
    [Array]::Sort($sorted, [System.StringComparer]::Ordinal)
    return ($sorted -join "`n")
}
