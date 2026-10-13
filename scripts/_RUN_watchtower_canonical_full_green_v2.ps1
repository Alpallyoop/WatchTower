# Ecosystem-convention entry point for the canonical WatchTower Tier-0 gate (v2).
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\_RUN_watchtower_canonical_full_green_v2.ps1
#   pwsh -File scripts/_RUN_watchtower_canonical_full_green_v2.ps1 -Scope all -ReportPath ./test-report.json
#
# Success token: WATCHTOWER_TIER0_FULL_GREEN_OK suites=6 cases=<n>
# The legacy v1 runners in this folder are untouched; see docs/canonical/CURRENT_STATE.md.
param(
    [ValidateSet('standalone', 'interop', 'all')][string]$Scope = 'standalone',
    [string]$ReportPath = ''
)
& (Join-Path (Split-Path -Parent $PSScriptRoot) 'tests/Invoke-WatchTowerTests.ps1') -Scope $Scope -ReportPath $ReportPath
exit $LASTEXITCODE
