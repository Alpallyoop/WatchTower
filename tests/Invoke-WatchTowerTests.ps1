<#
.SYNOPSIS
    Runs the WatchTower test suites and emits the release gate token.

.DESCRIPTION
    standalone  Core, Packet, Telemetry, Ingest, Cli, Schemas, Integration. Needs nothing but PowerShell 5.1+
                and OpenSSH ssh-keygen. This is the Tier-0 gate:
                    WATCHTOWER_TIER0_FULL_GREEN_OK suites=7 cases=<n>
    interop     Interop: conformance against live-state-surgeon output and the real CPR,
                NeverLost, Arbiter and live-state-surgeon code when their checkouts are available:
                    WATCHTOWER_INTEROP_OK | WATCHTOWER_INTEROP_PARTIAL (some unavailable) | WATCHTOWER_INTEROP_FAIL
    all         both.

    Every suite runs in its own process. The repository is hashed before and after the run;
    any change fails the gate (REPO_MUTATED): verification must never mutate evidence.
    With -ReportPath, a canonical JSON report (watchtower.test_run.v1) is written, re-read and
    validated against schemas/watchtower.test_run.v1.json before any token is printed.
#>
[CmdletBinding()]
param(
    [ValidateSet('standalone', 'interop', 'all')][string]$Scope = 'standalone',
    [string]$ReportPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$tests = $PSScriptRoot
$repository = Split-Path -Parent $tests
$module = Import-Module (Join-Path $repository 'src/WatchTower/WatchTower.psd1') -Force -PassThru
$powershell = (Get-Process -Id $PID).Path

$suites = New-Object System.Collections.Generic.List[string]
if ($Scope -ne 'interop') { foreach ($s in @('Core', 'Packet', 'Telemetry', 'Ingest', 'Cli', 'Schemas', 'Integration')) { $suites.Add($s) } }
if ($Scope -ne 'standalone') { $suites.Add('Interop') }

function Get-RepositoryDigest {
    # Every file except .git, node_modules and the workspace scratch/cache folders (.scratch,
    # and .work/.cache that the dev-root DEV_SHELL creates), by relative path and content.
    $lines = New-Object System.Collections.Generic.List[string]
    $prefix = $repository.TrimEnd([char[]]@('\', '/')).Length + 1
    foreach ($file in [System.IO.Directory]::EnumerateFiles($repository, '*', [System.IO.SearchOption]::AllDirectories)) {
        $relative = $file.Substring($prefix).Replace('\', '/')
        if ($relative.StartsWith('.git/') -or $relative.StartsWith('.scratch/') -or $relative.StartsWith('.work/') -or $relative.StartsWith('.cache/') -or $relative -match '(^|/)node_modules/') { continue }
        $lines.Add($relative + "`t" + (& $module { param($p) Get-WtSha256 -Path $p } $file))
    }
    $sorted = $lines.ToArray()
    [Array]::Sort($sorted, [System.StringComparer]::Ordinal)
    return (& $module { param($t) Get-WtSha256 -Text $t } ($sorted -join "`n"))
}

$before = Get-RepositoryDigest
$results = New-Object System.Collections.ArrayList
foreach ($suite in $suites) {
    $script = Join-Path $tests ($suite + '.Tests.ps1')
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    # stderr is captured as text: on Windows PowerShell 5.1 a child's stderr line would
    # otherwise abort the runner under ErrorActionPreference 'Stop', losing every diagnostic.
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { 'STDERR: ' + $_.Exception.Message } else { [string]$_ }
        } | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = 'Stop' }
    $watch.Stop()
    $lines = @($output.Trim() -split "`r?`n")
    $final = $lines[$lines.Count - 1]
    $cases = 0; $skipped = 0
    if ($final -match 'cases=(\d+)') { $cases = [int]$Matches[1] }
    elseif ($final -match 'passed=(\d+)') { $cases = [int]$Matches[1] }
    if ($final -match 'skipped=(\d+)') { $skipped = [int]$Matches[1] }
    $ok = ($exitCode -eq 0) -and ($final -match '^WATCHTOWER_[A-Z]+_TESTS_OK\b')
    foreach ($line in $lines) { if ($line -match '^CASE_(FAIL|SKIP):') { Write-Output ('  ' + $line) } }
    Write-Output ('SUITE {0,-11} {1,-4} cases={2} skipped={3} seconds={4:0.0}' -f $suite, $(if ($ok) { 'OK' } else { 'FAIL' }), $cases, $skipped, $watch.Elapsed.TotalSeconds)
    [void]$results.Add([ordered]@{ suite = $suite; ok = $ok; exit_code = $exitCode; cases = $cases; skipped = $skipped; token = $final })
}
$after = Get-RepositoryDigest
$mutated = ($before -cne $after)
if ($mutated) { Write-Output 'REPO_MUTATED: the repository changed during the test run' }

$standalone = @($results | Where-Object { $_['suite'] -cne 'Interop' })
$interop = @($results | Where-Object { $_['suite'] -ceq 'Interop' })
$tokens = New-Object System.Collections.Generic.List[string]
$failed = $mutated
if ($standalone.Count -gt 0) {
    $cases = ($standalone | ForEach-Object { $_['cases'] } | Measure-Object -Sum).Sum
    if ($mutated -or @($standalone | Where-Object { -not $_['ok'] }).Count -gt 0) {
        $failedSuites = @($standalone | Where-Object { -not $_['ok'] } | ForEach-Object { $_['suite'] })
        if ($mutated) { $failedSuites += 'REPO_MUTATED' }
        $tokens.Add('WATCHTOWER_TIER0_FULL_GREEN_FAIL:' + ($failedSuites -join ','))
        $failed = $true
    }
    else { $tokens.Add(('WATCHTOWER_TIER0_FULL_GREEN_OK suites={0} cases={1}' -f $standalone.Count, $cases)) }
}
if ($interop.Count -gt 0) {
    $i = $interop[0]
    if (-not $i['ok']) { $tokens.Add('WATCHTOWER_INTEROP_FAIL'); $failed = $true }
    elseif ($i['skipped'] -gt 0) { $tokens.Add(('WATCHTOWER_INTEROP_PARTIAL cases={0} unavailable={1}' -f $i['cases'], $i['skipped'])) }
    else { $tokens.Add(('WATCHTOWER_INTEROP_OK cases={0}' -f $i['cases'])) }
}

if ($ReportPath) {
    # RuntimeInformation needs .NET Framework 4.7.1+; older hosts still get a report.
    $osDescription = try { [System.Runtime.InteropServices.RuntimeInformation]::OSDescription } catch { [Environment]::OSVersion.VersionString }
    $report = [ordered]@{
        schema          = 'watchtower.test_run.v1'
        generated_utc   = (& $module { Get-WtUtcNow })
        scope           = $Scope
        module_version  = $module.Version.ToString()
        powershell      = [ordered]@{ edition = [string]$PSVersionTable.PSEdition; version = $PSVersionTable.PSVersion.ToString() }
        os              = $osDescription
        repository_hash = $after
        repo_mutated    = $mutated
        suites          = $results
        tokens          = @($tokens)
    }
    & $module { param($p, $v) Write-WtJsonFile -Path $p -Value (Copy-WtJsonValue $v) } $ReportPath $report
    # Durable and verified before any token is printed.
    $reread = & $module { param($p) Read-WtJsonFile -Path $p -Object -Canonical } $ReportPath
    if ([string]$reread['repository_hash'] -cne $after) { Write-Output 'REPORT_VERIFY_FAILED'; exit 1 }
    $schemaErrors = & $module {
        param($validator, $schema, $value)
        . $validator
        Get-SchemaErrors -SchemaPath $schema -Value $value
    } (Join-Path $tests 'support/SchemaValidator.ps1') (Join-Path $repository 'schemas/watchtower.test_run.v1.json') $reread
    if (@($schemaErrors).Count -gt 0) { Write-Output ('REPORT_SCHEMA_INVALID: ' + (@($schemaErrors) -join '; ')); exit 1 }
    Write-Output ('REPORT: ' + $ReportPath)
}
foreach ($token in $tokens) { Write-Output $token }
if ($failed) { exit 1 }
exit 0
