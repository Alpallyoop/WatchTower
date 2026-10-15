# Policy gate: WatchTower as a consumer of Arbiter (registry integration watchtower > arbiter,
# contracts policy.policyset.v1, policy.input.v1, policy.decision.v1; Constellation proposal 0012,
# Arbiter proposal 0002, Arbiter docs/INTEGRATION.md).
#
# Optional and off by default: it runs only when config/watchtower.settings.json has an
# "arbiter" block. WatchTower stays standalone; Arbiter decides, WatchTower routes.
#
#   1. Only packets that passed every WatchTower check (PCv1, contract, pinned-trust signatures,
#      body rules, replay/order/clock rules) are evaluated. Transport integrity comes first.
#   2. A policy.input.v1 is built from verified facts only: env.now is the verification time,
#      trust.* comes from the pinned NeverLost bundle (Arbiter never resolves trust).
#   3. Arbiter's own evaluator runs as a child process (never imported), against a content-
#      addressed snapshot of the policy under proofs/policy/sets/<policy_hash>/.
#   4. The decision is re-verified, never trusted: strict canonical JSON, schema, engine,
#      evaluated_at = env.now, and policy_hash, input_hash and decision_hash recomputed here.
#   5. allow -> accepted; deny -> quarantined (POLICY_DENY); quarantine -> quarantined
#      (POLICY_QUARANTINE, obligations recorded). Any evaluator failure is a deny (fail closed):
#      POLICY_EVALUATOR_UNAVAILABLE / _TIMEOUT / _FAILED, POLICY_DECISION_INVALID, POLICY_SET_INVALID.
#   6. Every exchange writes a constellation.integration.receipt.v1 first (watchtower > arbiter);
#      the input and decision are kept under proofs/policy/{inputs,decisions}/<hash>.json so
#      anyone (LawVM: `arbiter verify`) can re-prove the decision from bytes.

$script:WtArbiterEngineScript = 'scripts/evaluate_arbiter_v1.ps1'
$script:WtPolicyFailureCodes = @('POLICY_EVALUATOR_UNAVAILABLE', 'POLICY_EVALUATOR_TIMEOUT', 'POLICY_EVALUATOR_FAILED', 'POLICY_DECISION_INVALID', 'POLICY_SET_INVALID', 'POLICY_EVIDENCE_CONFLICT')
$script:WtPolicyPrefixPattern = '^sha256:[0-9a-f]{64}$'

function Get-WtRepositoryRoot {
    [OutputType([string])]
    param()
    return [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..'))
}

function Find-WtArbiterEngine {
    # WATCHTOWER_ARBITER_ROOT, else a sibling checkout of this repository ('arbiter' / 'Arbiter',
    # the dev-root family layout). The engine location is machine-local and never enters evidence.
    [OutputType([string])]
    param()
    $candidates = New-Object System.Collections.Generic.List[string]
    $configured = [Environment]::GetEnvironmentVariable('WATCHTOWER_ARBITER_ROOT')
    if ($configured) { $candidates.Add($configured) }
    else {
        $parent = [System.IO.Path]::GetDirectoryName((Get-WtRepositoryRoot).TrimEnd([char[]]@('\', '/')))
        foreach ($name in @('arbiter', 'Arbiter')) { $candidates.Add([System.IO.Path]::Combine($parent, $name)) }
    }
    foreach ($candidate in $candidates) {
        $script = [System.IO.Path]::Combine($candidate, $script:WtArbiterEngineScript.Replace('/', [string][System.IO.Path]::DirectorySeparatorChar))
        if ([System.IO.File]::Exists($script)) { return [System.IO.Path]::GetFullPath($script) }
    }
    return ''
}

function Get-WtPowerShellHost {
    # The PowerShell executable running WatchTower (powershell.exe 5.1 or pwsh), so the policy
    # engine runs on the same edition.
    [OutputType([string])]
    param()
    # $PSHOME, not the host process: under the ISE or a custom host the process is not a shell.
    $names = $(if ($PSVersionTable.PSEdition -eq 'Desktop') { @('powershell.exe') } else { @('pwsh.exe', 'pwsh') })
    foreach ($name in $names) {
        $candidate = [System.IO.Path]::Combine($PSHOME, $name)
        if ([System.IO.File]::Exists($candidate)) { return $candidate }
    }
    throw (New-WtFailure 'POWERSHELL_HOST_NOT_FOUND' $PSHOME)
}

function Read-WtPolicyGate {
    # The policy gate for one ingest run, or $null when settings has no "arbiter" block. The
    # policy is read once per run; a policy that cannot be read is not an error here: every
    # evaluation of the run is then recorded as POLICY_SET_INVALID (fail closed, per packet).
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Settings, [switch]$ReadOnly)
    if (-not $Settings.Contains('arbiter')) { return $null }
    $config = $Settings['arbiter']
    $gate = [pscustomobject]@{
        PolicySetRelative = [string]$config['policyset']; PolicyRootRelative = [string]$config['policy_root']
        TimeoutSeconds = [int]$config['timeout_seconds']; Engine = (Find-WtArbiterEngine)
        PolicySet = $null; RuleDocs = $null; RuleFiles = $null; PolicyHash = ''; Snapshot = ''; Error = ''
    }
    try {
        $root = [System.IO.Path]::Combine($Layout.Root, $gate.PolicyRootRelative.Replace('/', [string][System.IO.Path]::DirectorySeparatorChar))
        $policySetPath = [System.IO.Path]::Combine($Layout.Root, $gate.PolicySetRelative.Replace('/', [string][System.IO.Path]::DirectorySeparatorChar))
        $policySetBytes = Read-WtBytes $policySetPath
        $policySet = ConvertFrom-WtJson (ConvertFrom-WtUtf8 -Bytes $policySetBytes -Source 'policyset')
        if ($policySet -isnot [System.Collections.IDictionary] -or -not ($policySet['schema'] -is [string]) -or $policySet['schema'] -cne 'policy.policyset.v1') { throw (New-WtFailure 'POLICY_SET_SCHEMA') }
        if (-not ($policySet['engine'] -is [string]) -or $policySet['engine'] -cne 'arbiter.v1') { throw (New-WtFailure 'POLICY_SET_ENGINE') }
        $ruleFiles = Get-WtField $policySet 'rule_files' 'array' 'policyset'
        if ($ruleFiles.Count -lt 1) { throw (New-WtFailure 'POLICY_SET_NO_RULE_FILES') }
        $docs = New-Object System.Collections.ArrayList
        $files = New-Object System.Collections.ArrayList
        foreach ($relative in $ruleFiles) {
            if (-not ($relative -is [string])) { throw (New-WtFailure 'POLICY_RULE_FILE_PATH') }
            Assert-WtSafeRelativePath $relative
            $bytes = Read-WtBytes ([System.IO.Path]::Combine($root, $relative.Replace('/', [string][System.IO.Path]::DirectorySeparatorChar)))
            $doc = ConvertFrom-WtJson (ConvertFrom-WtUtf8 -Bytes $bytes -Source $relative)
            if ($doc -isnot [System.Collections.IDictionary] -or [string]$doc['schema'] -cne 'policy.rule_file.v1') { throw (New-WtFailure 'POLICY_RULE_FILE_SCHEMA' $relative) }
            [void]$docs.Add($doc)
            [void]$files.Add([pscustomobject]@{ Relative = $relative; Bytes = $bytes })
        }
        $gate.PolicySet = $policySet
        $gate.RuleDocs = $docs
        $gate.PolicyHash = Get-WtArbiterPolicyHash -PolicySet $policySet -RuleDocs $docs
        if (-not $ReadOnly) { $gate.Snapshot = Save-WtPolicySnapshot -Layout $Layout -PolicyHash $gate.PolicyHash -PolicySetBytes $policySetBytes -RuleFiles $files }
    }
    catch { $gate.Error = Get-WtFailureCode $_ }
    return $gate
}

function Get-WtArbiterPolicyHash {
    # Arbiter's policy_hash: sha256(canonical({"policyset": ..., "rule_files": [docs in order]}) + LF).
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$PolicySet, [Parameter(Mandatory = $true)]$RuleDocs)
    $bundle = New-WtObject
    $bundle['policyset'] = $PolicySet
    $bundle['rule_files'] = [object[]]@($RuleDocs)
    return 'sha256:' + (Get-WtCanonicalHash $bundle)
}

function Get-WtArbiterDecisionHash {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Decision)
    $copy = New-WtObject
    foreach ($key in $Decision.PSBase.Keys) { if ([string]$key -cne 'decision_hash' -and [string]$key -cne 'signature') { $copy[[string]$key] = $Decision[$key] } }
    return 'sha256:' + (Get-WtCanonicalHash $copy)
}

function Save-WtPolicySnapshot {
    # proofs/policy/sets/<hex>/policyset.json + every rule file at its relative path, byte-exact.
    # Write-once: an existing snapshot must reproduce the same policy_hash.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)][string]$PolicyHash, [Parameter(Mandatory = $true)][byte[]]$PolicySetBytes, [Parameter(Mandatory = $true)]$RuleFiles)
    $sets = [System.IO.Path]::Combine($Layout.PolicyEvidence, 'sets')
    $final = [System.IO.Path]::Combine($sets, $PolicyHash.Substring(7))
    if ([System.IO.Directory]::Exists($final)) {
        $existing = Read-WtPolicySnapshot -Directory $final
        if ($existing.PolicyHash -cne $PolicyHash) { throw (New-WtFailure 'POLICY_EVIDENCE_CONFLICT' ('sets/' + $PolicyHash.Substring(7))) }
        return $final
    }
    $build = [System.IO.Path]::Combine($sets, ('_build_' + [guid]::NewGuid().ToString('N')))
    try {
        Write-WtBytes -Path ([System.IO.Path]::Combine($build, 'policyset.json')) -Bytes $PolicySetBytes
        foreach ($file in $RuleFiles) {
            $target = [System.IO.Path]::Combine($build, 'rules', $file.Relative.Replace('/', [string][System.IO.Path]::DirectorySeparatorChar))
            Write-WtBytes -Path $target -Bytes $file.Bytes
        }
        if ((Read-WtPolicySnapshot -Directory $build).PolicyHash -cne $PolicyHash) { throw (New-WtFailure 'POLICY_EVIDENCE_CONFLICT' 'snapshot does not reproduce policy_hash') }
        try { Invoke-WtFsRetry { [System.IO.Directory]::Move($build, $final) } }
        catch { if (-not [System.IO.Directory]::Exists($final)) { throw } }
    }
    finally { Remove-WtTree $build }
    return $final
}

function Read-WtPolicySnapshot {
    # Recomputes policy_hash from a snapshot's bytes (rule_files resolve under <snapshot>/rules).
    param([Parameter(Mandatory = $true)][string]$Directory)
    $policySet = Read-WtJsonFile -Path ([System.IO.Path]::Combine($Directory, 'policyset.json')) -Object
    $docs = New-Object System.Collections.ArrayList
    foreach ($relative in (Get-WtField $policySet 'rule_files' 'array' 'policyset')) {
        Assert-WtSafeRelativePath ([string]$relative)
        [void]$docs.Add((Read-WtJsonFile -Path ([System.IO.Path]::Combine($Directory, 'rules', ([string]$relative).Replace('/', [string][System.IO.Path]::DirectorySeparatorChar))) -Object))
    }
    return [pscustomobject]@{ PolicyHash = (Get-WtArbiterPolicyHash -PolicySet $policySet -RuleDocs $docs); PolicySetPath = [System.IO.Path]::Combine($Directory, 'policyset.json'); RulesRoot = [System.IO.Path]::Combine($Directory, 'rules') }
}

function New-WtPolicyInput {
    # policy.input.v1 from verified facts only.
    param(
        [Parameter(Mandatory = $true)]$Verdict, [Parameter(Mandatory = $true)]$Facts, [Parameter(Mandatory = $true)]$Bundle,
        [Parameter(Mandatory = $true)]$Authority, [Parameter(Mandatory = $true)][string]$VerifiedUtc
    )
    $environment = New-WtObject
    $environment['now'] = $VerifiedUtc
    $environment['mode'] = 'ingest'
    $verifier = New-WtObject
    $verifier['principal'] = $Authority.Principal
    $verifier['key_id'] = $Authority.KeyId
    $verifier['product'] = 'watchtower'
    $verifier['instance'] = $Authority.NodeId
    $environment['verifier'] = $verifier

    $signer = New-WtObject
    $signer['principal'] = $Verdict.Producer
    $signer['key_id'] = $Verdict.KeyId
    $signer['alg'] = 'ssh-ed25519'
    $hashes = New-WtObject
    $hashes['artifact_hash'] = 'sha256:' + $Verdict.EventHash
    $hashes['manifest_hash'] = 'sha256:' + $Verdict.PacketId
    $claims = New-WtObject
    $claims['event_type'] = $Verdict.EventType
    $claims['event_id'] = $Verdict.EventId
    $claims['device_id'] = $Verdict.DeviceId
    $claims['seq'] = [long]$Verdict.Seq
    $claims['health_status'] = $Facts.HealthStatus
    $claims['compliance'] = $Facts.Compliance
    $claims['policy_check'] = $Facts.PolicyCheck
    $claims['posture_hash'] = $Facts.PostureHash
    $claims['policy_hash_claimed'] = $Facts.PolicyHashClaimed
    $alertState = ''
    if ($Verdict.EventType -ceq 'watchtower.alert.v1' -and $Verdict.Event['body']['state'] -is [string]) { $alertState = [string]$Verdict.Event['body']['state'] }
    $claims['alert_state'] = $alertState
    $artifact = New-WtObject
    $artifact['namespace'] = $Verdict.Namespace
    $artifact['created_at'] = $Verdict.ProducerTime
    $artifact['observed_at'] = $Verdict.ProducerTime
    $artifact['producer'] = $Verdict.Producer
    $artifact['producer_instance'] = $Verdict.ProducerInstance
    $artifact['signer'] = $signer
    $artifact['hashes'] = $hashes
    $artifact['claims'] = $claims

    # Trust facts, resolved by WatchTower from its pinned bundle: the producer's own grants.
    $namespaces = New-Object 'System.Collections.Generic.SortedSet[string]' ([System.StringComparer]::Ordinal)
    $keyIds = New-Object 'System.Collections.Generic.SortedSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($entry in $Bundle['principals']) {
        if ([string]$entry['principal'] -cne $Verdict.Producer) { continue }
        foreach ($key in $entry['keys']) {
            [void]$keyIds.Add([string]$key['key_id'])
            foreach ($ns in $key['namespaces']) { [void]$namespaces.Add([string]$ns) }
        }
    }
    $trust = New-WtObject
    $trust['allowed_namespaces'] = [string[]]@($namespaces)
    $trust['allowed_key_ids'] = [string[]]@($keyIds)
    $trust['allowed_principals'] = [string[]]@($Verdict.Producer)

    $policyInput = New-WtObject
    $policyInput['schema'] = 'policy.input.v1'
    $policyInput['env'] = $environment
    $policyInput['artifact'] = $artifact
    $policyInput['trust'] = $trust
    return , (Copy-WtJsonValue $policyInput)
}

function Save-WtPolicyEvidence {
    # Write-once, content-addressed: proofs/policy/<kind>/<hex>.json. Existing bytes must match.
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)][string]$Kind, [Parameter(Mandatory = $true)][string]$Hex, [Parameter(Mandatory = $true)][byte[]]$Bytes)
    $path = [System.IO.Path]::Combine($Layout.PolicyEvidence, $Kind, $Hex + '.json')
    if ([System.IO.File]::Exists($path)) {
        if ((Get-WtSha256 -Path $path) -cne (Get-WtSha256 -Bytes $Bytes)) { throw (New-WtFailure 'POLICY_EVIDENCE_CONFLICT' ('{0}/{1}' -f $Kind, $Hex)) }
        return $path
    }
    Write-WtBytes -Path $path -Bytes $Bytes
    return $path
}

function Assert-WtPolicyDecision {
    # Re-verifies a decision from its bytes. Returns the parsed decision.
    param([Parameter(Mandatory = $true)][byte[]]$DecisionBytes, [Parameter(Mandatory = $true)][string]$InputHash, [Parameter(Mandatory = $true)][string]$PolicyHash, [Parameter(Mandatory = $true)][string]$Now)
    $text = ConvertFrom-WtUtf8 -Bytes $DecisionBytes -Source 'decision'
    $decision = ConvertFrom-WtJson $text
    if ($decision -isnot [System.Collections.IDictionary]) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'not an object') }
    if (((ConvertTo-WtCanonicalJson $decision) + "`n") -cne $text) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'not canonical') }
    $allowed = @('schema', 'engine', 'engine_version', 'evaluated_at', 'decision', 'matched_rule_id', 'reasons', 'obligations', 'policy_hash', 'input_hash', 'decision_hash', 'signature')
    foreach ($key in $decision.PSBase.Keys) { if ($allowed -cnotcontains [string]$key) { throw (New-WtFailure 'POLICY_DECISION_INVALID' ('unknown field ' + $key)) } }
    foreach ($key in @('schema', 'engine', 'engine_version', 'evaluated_at', 'decision', 'matched_rule_id', 'reasons', 'policy_hash', 'input_hash', 'decision_hash')) {
        if (-not $decision.Contains($key)) { throw (New-WtFailure 'POLICY_DECISION_INVALID' ('missing ' + $key)) }
    }
    # Type first: a JSON array on the left of -cne would filter instead of compare.
    foreach ($key in @('schema', 'engine', 'engine_version', 'evaluated_at', 'decision', 'policy_hash', 'input_hash', 'decision_hash')) {
        if (-not ($decision[$key] -is [string])) { throw (New-WtFailure 'POLICY_DECISION_INVALID' ($key + ' is not a string')) }
    }
    if ($decision['schema'] -cne 'policy.decision.v1' -or $decision['engine'] -cne 'arbiter.v1') { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'schema/engine') }
    if (-not ($decision['engine_version'] -is [string]) -or $decision['engine_version'].Length -eq 0) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'engine_version') }
    if (@('allow', 'deny', 'quarantine') -cnotcontains $decision['decision']) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'decision') }
    if ($null -ne $decision['matched_rule_id'] -and -not ($decision['matched_rule_id'] -is [string])) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'matched_rule_id') }
    $reasons = $decision['reasons']
    if ($reasons -isnot [System.Collections.IList] -or $reasons.Count -lt 1) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'reasons') }
    foreach ($reason in $reasons) { if (-not ($reason -is [string]) -or $reason.Length -eq 0) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'reasons') } }
    if ($decision.Contains('obligations')) {
        if ($decision['obligations'] -isnot [System.Collections.IList] -or $decision['obligations'] -is [System.Collections.IDictionary]) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'obligations') }
        foreach ($obligation in $decision['obligations']) {
            if ($obligation -isnot [System.Collections.IDictionary] -or -not ($obligation['type'] -is [string]) -or $obligation['type'].Length -eq 0) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'obligation') }
            foreach ($field in $obligation.PSBase.Keys) { if (@('type', 'params') -cnotcontains [string]$field) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'obligation field') } }
            if ($obligation.Contains('params') -and $obligation['params'] -isnot [System.Collections.IDictionary]) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'obligation params') }
        }
    }
    if ($decision['evaluated_at'] -cne $Now) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'evaluated_at is not env.now') }
    # Stored hashes are recomputed, never trusted.
    if ($decision['input_hash'] -cne $InputHash) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'input_hash') }
    if ($decision['policy_hash'] -cne $PolicyHash) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'policy_hash') }
    if ($decision['decision_hash'] -cnotmatch $script:WtPolicyPrefixPattern -or $decision['decision_hash'] -cne (Get-WtArbiterDecisionHash $decision)) { throw (New-WtFailure 'POLICY_DECISION_INVALID' 'decision_hash') }
    return , $decision
}

function Invoke-WtPolicyGate {
    # One exchange with Arbiter for one verified packet. Always writes exactly one integration
    # receipt, then returns the outcome WatchTower routes on.
    param(
        [Parameter(Mandatory = $true)]$Gate, [Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Verdict,
        [Parameter(Mandatory = $true)]$Facts, [Parameter(Mandatory = $true)]$Bundle, [Parameter(Mandatory = $true)]$Authority,
        [Parameter(Mandatory = $true)][string]$VerifiedUtc
    )
    $result = [pscustomobject]@{
        Decision = 'deny'; Code = ''; Detail = ''; Outcome = ''; ErrorToken = ''; Reasons = @(); Obligations = @(); MatchedRuleId = ''
        EngineVersion = ''; PolicyHash = $Gate.PolicyHash; InputHash = ''; DecisionHash = ''; IntegrationReceiptSha256 = ''
    }
    $requestSha = ''
    $responseSha = ''
    $carried = @()
    $work = $null
    # Machine paths (state root, engine checkout) never enter evidence.
    $scrub = @($Layout.Root, (Get-WtTempRoot))
    if ($Gate.Engine) { $scrub += [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetDirectoryName($Gate.Engine)) }
    try {
        $policyInput = New-WtPolicyInput -Verdict $Verdict -Facts $Facts -Bundle $Bundle -Authority $Authority -VerifiedUtc $VerifiedUtc
        $inputBytes = ConvertTo-WtUtf8 ((ConvertTo-WtCanonicalJson $policyInput) + "`n")
        $inputHex = Get-WtSha256 -Bytes $inputBytes
        $result.InputHash = 'sha256:' + $inputHex
        if ($Gate.Error) {
            $result.Code = 'POLICY_SET_INVALID'; $result.Outcome = 'refused'; $result.ErrorToken = 'POLICY_SET_INVALID'; $result.Detail = $Gate.Error
        }
        elseif (-not $Gate.Engine) {
            $result.Code = 'POLICY_EVALUATOR_UNAVAILABLE'; $result.Outcome = 'unavailable'; $result.ErrorToken = 'ARBITER_NOT_FOUND'
            $result.Detail = 'set WATCHTOWER_ARBITER_ROOT or place an arbiter checkout beside this repository'
        }
        else {
            [void](Save-WtPolicyEvidence -Layout $Layout -Kind 'inputs' -Hex $inputHex -Bytes $inputBytes)
            $work = New-WtTempDirectory 'wtpolicy'
            $scrub = @($work) + $scrub
            $inputPath = Join-Path $work 'input.json'
            $decisionPath = Join-Path $work 'decision.json'
            Write-WtBytes -Path $inputPath -Bytes $inputBytes
            $snapshot = Read-WtPolicySnapshot -Directory $Gate.Snapshot
            $requestSha = $inputHex
            $timeout = [Math]::Max(1, $Gate.TimeoutSeconds) * 1000
            $run = $null
            try {
                $run = Invoke-WtNative -FilePath (Get-WtPowerShellHost) -TimeoutMilliseconds $timeout -ArgumentList @(
                    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Gate.Engine,
                    '-RepoRoot', $snapshot.RulesRoot, '-PolicySetPath', $snapshot.PolicySetPath, '-InputPath', $inputPath, '-OutDecisionPath', $decisionPath)
            }
            catch {
                $code = Get-WtFailureCode $_
                if ($code -ceq 'NATIVE_TIMEOUT') { $result.Code = 'POLICY_EVALUATOR_TIMEOUT'; $result.Outcome = 'unknown'; $result.ErrorToken = 'ARBITER_TIMEOUT' }
                else { $result.Code = 'POLICY_EVALUATOR_UNAVAILABLE'; $result.Outcome = 'unavailable'; $result.ErrorToken = 'ARBITER_LAUNCH_FAILED'; $requestSha = '' }
                $result.Detail = $code
            }
            if ($null -ne $run) {
                # Only machine-independent bytes are hashed: the evaluator's output with paths scrubbed.
                $outputBytes = ConvertTo-WtUtf8 (Protect-WtDetail -Detail ([string]$run.Stdout + [string]$run.Stderr) -Roots $scrub)
                if ($run.ExitCode -ne 0 -or -not [System.IO.File]::Exists($decisionPath)) {
                    $token = [regex]::Match([string]$run.Stderr + [string]$run.Stdout, '\b(ARBITER_E_[A-Z0-9_]+)\b')
                    $result.Code = 'POLICY_EVALUATOR_FAILED'; $result.Outcome = 'failed'
                    $result.ErrorToken = $(if ($token.Success) { $token.Groups[1].Value } else { 'ARBITER_EXIT_' + [string]$run.ExitCode -replace '-', 'M' })
                    $result.Detail = Limit-WtText (Protect-WtDetail -Detail ([string]$run.Stderr).Trim() -Roots $scrub) 256
                    if ($outputBytes.Length -gt 0) { $responseSha = Get-WtSha256 -Bytes $outputBytes }
                }
                else {
                    $decisionBytes = [System.IO.File]::ReadAllBytes($decisionPath)
                    $responseSha = Get-WtSha256 -Bytes $decisionBytes
                    try {
                        $decision = Assert-WtPolicyDecision -DecisionBytes $decisionBytes -InputHash $result.InputHash -PolicyHash $Gate.PolicyHash -Now $VerifiedUtc
                        [void](Save-WtPolicyEvidence -Layout $Layout -Kind 'decisions' -Hex ([string]$decision['decision_hash']).Substring(7) -Bytes $decisionBytes)
                        $result.Decision = [string]$decision['decision']
                        $result.Reasons = [string[]]@($decision['reasons'] | Select-Object -First 32 | ForEach-Object { Limit-WtText ([string]$_) 128 })
                        $result.MatchedRuleId = $(if ($null -eq $decision['matched_rule_id']) { '' } else { Limit-WtText ([string]$decision['matched_rule_id']) 114 })
                        $result.EngineVersion = Limit-WtText ([string]$decision['engine_version']) 50
                        $result.DecisionHash = [string]$decision['decision_hash']
                        if ($decision.Contains('obligations')) { $result.Obligations = @($decision['obligations'] | Select-Object -First 16) }
                        $result.Outcome = 'ok'
                        $carried = @([pscustomobject]@{ Contract = 'policy.decision.v1'; Sha256 = $result.DecisionHash.Substring(7) })
                        switch -CaseSensitive ($result.Decision) {
                            'allow' { $result.Code = '' }
                            'deny' { $result.Code = 'POLICY_DENY' }
                            'quarantine' { $result.Code = 'POLICY_QUARANTINE' }
                        }
                        $result.Detail = ($result.Reasons -join ',')
                    }
                    catch {
                        $code = Get-WtFailureCode $_
                        $result.Decision = 'deny'
                        $result.Code = $(if ($code -ceq 'POLICY_EVIDENCE_CONFLICT') { 'POLICY_EVIDENCE_CONFLICT' } else { 'POLICY_DECISION_INVALID' })
                        $result.Outcome = 'failed'; $result.ErrorToken = $result.Code
                        $result.Detail = Limit-WtText (Protect-WtDetail -Detail (Get-WtFailureMessage $_) -Roots $scrub) 256
                    }
                }
            }
        }
    }
    catch {
        # Anything unexpected on WatchTower's side still ends as a recorded, failed exchange.
        $result.Decision = 'deny'; $result.Code = 'POLICY_EVALUATOR_FAILED'; $result.Outcome = 'failed'
        $result.ErrorToken = 'WATCHTOWER_' + (Get-WtFailureCode $_); $result.Detail = Limit-WtText (Protect-WtDetail -Detail (Get-WtFailureMessage $_) -Roots $scrub) 256
    }
    finally { if ($work) { Remove-WtTree $work } }
    if ($result.Outcome -cne 'ok') { $result.Decision = 'deny' }

    $receipt = New-WtIntegrationReceipt -Provider 'arbiter' -Contract 'policy.decision.v1' -RequestSha256 $requestSha -ResponseSha256 $responseSha `
        -Outcome $result.Outcome -ErrorToken $result.ErrorToken -Carried $carried
    $result.IntegrationReceiptSha256 = (Add-WtIntegrationReceipt -Layout $Layout -Receipt $receipt).ReceiptSha256
    return $result
}

function ConvertTo-WtPolicyBlock {
    # The receipt row's policy_decision block (watchtower.policy_gate.v1). Every field present.
    param([Parameter(Mandatory = $true)]$Result)
    $block = New-WtObject
    $block['schema'] = $script:WtPolicyGateSchema
    $block['engine'] = 'arbiter.v1'
    $block['engine_version'] = $Result.EngineVersion
    $block['decision'] = $Result.Decision
    $block['matched_rule_id'] = $Result.MatchedRuleId
    $block['reasons'] = [string[]]@($Result.Reasons)
    $types = New-Object System.Collections.ArrayList
    foreach ($obligation in $Result.Obligations) { [void]$types.Add((Limit-WtText ([string]$obligation['type']) 64)) }
    $block['obligations'] = $types
    $block['policy_hash'] = $Result.PolicyHash
    $block['input_hash'] = $Result.InputHash
    $block['decision_hash'] = $Result.DecisionHash
    $block['outcome'] = $Result.Outcome
    $block['error_token'] = $Result.ErrorToken
    $block['integration_receipt_sha256'] = $Result.IntegrationReceiptSha256
    return , $block
}

function Test-WtPolicyEvidence {
    # Re-proves one receipt's policy decision from stored bytes (Test-WtLedger).
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)]$Row, [Parameter(Mandatory = $true)]$ArbiterHashes, [Parameter(Mandatory = $true)]$Warnings)
    $block = $Row['policy_decision']
    $id = [string]$Row['receipt_hash']
    if ($block -isnot [System.Collections.IDictionary] -or [string]$block['schema'] -cne $script:WtPolicyGateSchema) { throw (New-WtFailure 'LEDGER_POLICY_BLOCK' $id) }
    if (-not $ArbiterHashes.ContainsKey([string]$block['integration_receipt_sha256'])) { throw (New-WtFailure 'LEDGER_POLICY_RECEIPT_UNLINKED' $id) }
    # The linked integration receipt tells the same story as the block.
    $linked = $ArbiterHashes[[string]$block['integration_receipt_sha256']]
    if ([string]$linked['outcome'] -cne [string]$block['outcome']) { throw (New-WtFailure 'LEDGER_POLICY_RECEIPT_MISMATCH' $id) }
    if ([string]$block['outcome'] -ceq 'ok') {
        if ($linked['carried'].Count -ne 1 -or ('sha256:' + [string]$linked['carried'][0]['sha256']) -cne [string]$block['decision_hash'] -or ('sha256:' + [string]$linked['request_sha256']) -cne [string]$block['input_hash']) {
            throw (New-WtFailure 'LEDGER_POLICY_RECEIPT_MISMATCH' $id)
        }
    }
    $accepted = [string]$Row['verify_result'] -ceq 'ok'
    if ($accepted -and ([string]$block['decision'] -cne 'allow' -or [string]$block['outcome'] -cne 'ok')) { throw (New-WtFailure 'LEDGER_POLICY_ACCEPTED_WITHOUT_ALLOW' $id) }
    if ([string]$block['outcome'] -cne 'ok') { return }
    $decisionHash = [string]$block['decision_hash']
    $inputHash = [string]$block['input_hash']
    $policyHash = [string]$block['policy_hash']
    foreach ($value in @($decisionHash, $inputHash, $policyHash)) { if ($value -cnotmatch $script:WtPolicyPrefixPattern) { throw (New-WtFailure 'LEDGER_POLICY_BLOCK' $id) } }
    $decisionPath = [System.IO.Path]::Combine($Layout.PolicyEvidence, 'decisions', $decisionHash.Substring(7) + '.json')
    $inputPath = [System.IO.Path]::Combine($Layout.PolicyEvidence, 'inputs', $inputHash.Substring(7) + '.json')
    $setPath = [System.IO.Path]::Combine($Layout.PolicyEvidence, 'sets', $policyHash.Substring(7))
    foreach ($path in @($decisionPath, $inputPath)) { if (-not [System.IO.File]::Exists($path)) { [void]$Warnings.Add('POLICY_EVIDENCE_ABSENT ' + (Get-WtRootRelative $Layout $path)); return } }
    if (-not [System.IO.Directory]::Exists($setPath)) { [void]$Warnings.Add('POLICY_EVIDENCE_ABSENT ' + (Get-WtRootRelative $Layout $setPath)); return }
    if ('sha256:' + (Get-WtSha256 -Path $inputPath) -cne $inputHash) { throw (New-WtFailure 'LEDGER_POLICY_INPUT' $id) }
    if ((Read-WtPolicySnapshot -Directory $setPath).PolicyHash -cne $policyHash) { throw (New-WtFailure 'LEDGER_POLICY_SET' $id) }
    $policyInput = Read-WtJsonFile -Path $inputPath -Object -Canonical
    # The input is about this row's packet and event, not another one's.
    $hashes = $policyInput['artifact']['hashes']
    if ([string]$hashes['manifest_hash'] -cne ('sha256:' + [string]$Row['packet_id']) -or [string]$hashes['artifact_hash'] -cne ('sha256:' + [string]$Row['event_hash'])) { throw (New-WtFailure 'LEDGER_POLICY_INPUT' ('{0} names another packet' -f $id)) }
    try { $decision = Assert-WtPolicyDecision -DecisionBytes ([System.IO.File]::ReadAllBytes($decisionPath)) -InputHash $inputHash -PolicyHash $policyHash -Now ([string]$policyInput['env']['now']) }
    catch { throw (New-WtFailure 'LEDGER_POLICY_DECISION' ('{0} {1}' -f $id, (Get-WtFailureMessage $_))) }
    if ([string]$decision['decision_hash'] -cne $decisionHash -or [string]$decision['decision'] -cne [string]$block['decision']) { throw (New-WtFailure 'LEDGER_POLICY_DECISION' $id) }
}
