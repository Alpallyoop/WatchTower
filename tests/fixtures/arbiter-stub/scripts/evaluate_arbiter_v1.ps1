# Test double for Arbiter's evaluator (same command line and exit contract as Arbiter's
# scripts/evaluate_arbiter_v1.ps1). It is NOT Arbiter: it ignores the rules and decides from
# the device_id claim so the standalone suite can drive every outcome WatchTower must handle.
# Real Arbiter is exercised by tests/Interop.Tests.ps1.
#   allow (default) | deny-* | quar-* | crash-* (exit 1, no file) | badhash-* | staleat-* | arrays-* | sleep-*
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$PolicySetPath,
    [Parameter(Mandatory = $true)][string]$InputPath,
    [Parameter(Mandatory = $true)][string]$OutDecisionPath
)
$ErrorActionPreference = 'Stop'
$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$module = Import-Module (Join-Path $repository 'src/WatchTower/WatchTower.psd1') -Force -PassThru
$decision = & $module {
    param($root, $policySetPath, $inputPath)
    $policyInput = Read-WtJsonFile -Path $inputPath -Object -Canonical
    $policySet = Read-WtJsonFile -Path $policySetPath -Object
    $docs = @(foreach ($relative in $policySet['rule_files']) { Read-WtJsonFile -Path (Join-Path $root ([string]$relative)) -Object })
    $device = [string]$policyInput['artifact']['claims']['device_id']
    $d = New-WtObject
    $d['schema'] = 'policy.decision.v1'
    $d['engine'] = 'arbiter.v1'
    $d['engine_version'] = 'stub-1'
    $d['evaluated_at'] = [string]$policyInput['env']['now']
    $d['decision'] = 'allow'; $d['matched_rule_id'] = 'STUB_ALLOW'; $d['reasons'] = @('STUB_ALLOW'); $d['obligations'] = @()
    if ($device.StartsWith('deny-')) { $d['decision'] = 'deny'; $d['matched_rule_id'] = 'STUB_DENY'; $d['reasons'] = @('STUB_DENY') }
    if ($device.StartsWith('quar-')) {
        $d['decision'] = 'quarantine'; $d['matched_rule_id'] = $null; $d['reasons'] = @('STUB_QUARANTINE')
        $route = New-WtObject; $route['type'] = 'route_to_quarantine'; $params = New-WtObject; $params['queue'] = 'stub'; $route['params'] = $params
        $notify = New-WtObject; $notify['type'] = 'notify_operator'
        $d['obligations'] = @($route, $notify)
    }
    if ($device.StartsWith('staleat-')) { $d['evaluated_at'] = '2000-01-01T00:00:00Z' }
    $bundle = New-WtObject; $bundle['policyset'] = $policySet; $bundle['rule_files'] = [object[]]$docs
    $d['policy_hash'] = 'sha256:' + (Get-WtCanonicalHash $bundle)
    $d['input_hash'] = 'sha256:' + (Get-WtSha256 -Path $inputPath)
    $d['decision_hash'] = 'sha256:' + (Get-WtCanonicalHash $d)
    if ($device.StartsWith('badhash-')) { $d['decision_hash'] = 'sha256:' + ('0' * 64) }
    if ($device.StartsWith('arrays-')) {
        # Self-consistent but typeless: arrays where strings belong, hash recomputed to match.
        foreach ($k in @('schema', 'engine', 'evaluated_at', 'policy_hash', 'input_hash')) { $d[$k] = @() }
        $d['decision'] = @('allow'); $d.Remove('decision_hash')
        $d['decision_hash'] = 'sha256:' + (Get-WtCanonicalHash $d)
    }
    return , $d
} $RepoRoot $PolicySetPath $InputPath
$device = [string]((Get-Content -Raw -LiteralPath $InputPath | ConvertFrom-Json).artifact.claims.device_id)
if ($device.StartsWith('crash-')) { [Console]::Error.WriteLine('ARBITER_E_STUB: crash requested'); exit 1 }
if ($device.StartsWith('sleep-')) { Start-Sleep -Seconds 20 }
& $module { param($p, $v) Write-WtJsonFile -Path $p -Value $v } $OutDecisionPath $decision
[Console]::Out.WriteLine('DECISION_WROTE: stub')
exit 0
