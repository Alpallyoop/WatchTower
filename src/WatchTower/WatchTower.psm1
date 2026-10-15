# WatchTower - deterministic verifier and telemetry receipt authority.
# Module loader: private implementation first (fixed order), then the public cmdlets.
# Exports are declared explicitly in WatchTower.psd1.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$private = @(
    'Errors', 'IO', 'Json', 'Paths', 'Native', 'Trust', 'HashChain',
    'Constants', 'Layout', 'Authority', 'TelemetryRules', 'IngestRules', 'Evidence', 'Outbound', 'Integration', 'PolicyGate'
)
foreach ($name in $private) { . (Join-Path $PSScriptRoot ('Private/{0}.ps1' -f $name)) }
foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' | Sort-Object Name)) { . $file.FullName }
