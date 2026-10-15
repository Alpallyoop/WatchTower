<#
.SYNOPSIS
    WatchTower command line: deterministic verifier and telemetry receipt authority.

.DESCRIPTION
    Commands
      init                       Create or validate this node's authority key and NeverLost trust bundle.
      enroll                     Enroll a telemetry producer (-Principal -KeyId -PublicKey [-Namespace] [-AllowTestKey]),
                                 or from a NeverLost-issued bundle (-FromBundle <trust_bundle.json> -Principal
                                 [-KeyId] [-BundleRoot] [-NeverLostReceipt <file>] [-Namespace]).
      trust                      Show the trust bundle and confirm allowed_signers is exactly derived.
      verify-packet <path>       Verify a Packet Constitution v1 (Option A) packet. Never modifies it.
      verify-telemetry <path>    Verify a signed telemetry packet against this node's pinned trust.
      ingest                     Verify everything in packets/inbox and record receipts and evidence.
      ledger                     Re-verify every ledger, signature and cross-link from bytes.
      doctor                     Self-check this node ([-Publish] signs a health report for Constellation).
      index                      Rewrite runtime/evidence_index.json.
      integrations               Re-verify the Constellation integration receipts ([-Witness] hands new ones to NFL).
      version                    Print the module version.

    Output is key=value lines ending in one token:
      WATCHTOWER_<COMMAND>_OK            exit code 0
      WATCHTOWER_<COMMAND>_FAIL:<CODE>   exit code 1
    -Json prints the result as canonical JSON instead (the token line is still printed last).

.PARAMETER Root
    State root (defaults to the repository root). See docs/canonical/SPEC.md for the layout.

.PARAMETER VerificationTime
    Explicit evaluation time (YYYY-MM-DDTHH:MM:SSZ). Defaults to now and is recorded in every artifact.

.EXAMPLE
    pwsh -File bin/watchtower.ps1 init
.EXAMPLE
    pwsh -File bin/watchtower.ps1 enroll -Principal lss -KeyId lss-ed25519 -PublicKey ./lss_ed25519.pub
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File bin\watchtower.ps1 ingest
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(Position = 1)][string]$Path = '',
    [string]$Root = '',
    [string]$VerificationTime = '',
    [string]$Principal = '',
    [string]$KeyId = '',
    [string]$PublicKey = '',
    [string[]]$Namespace = @(),
    [string]$FromBundle = '',
    [string]$BundleRoot = '',
    [string]$NeverLostReceipt = '',
    [switch]$AllowTestKey,
    [switch]$Publish,
    [switch]$Witness,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = Split-Path -Parent $PSScriptRoot
$module = Import-Module (Join-Path $repository 'src/WatchTower/WatchTower.psd1') -Force -PassThru
if (-not $Root) { $Root = $repository }
$name = $Command.ToLowerInvariant()
$token = 'WATCHTOWER_' + ($name.ToUpperInvariant() -replace '[^A-Z0-9]', '_')

function Write-Field {
    param([string]$Key, [AllowNull()][AllowEmptyString()]$Value)
    Write-Output ('{0}={1}' -f $Key, $Value)
}

function Complete-Command {
    # Prints the result, then the token; exits 0 on success, 1 on failure.
    param([bool]$Ok, [string]$Code = 'OK', [AllowNull()]$Result = $null, [scriptblock]$Fields = $null)
    if ($Json -and $null -ne $Result) {
        Write-Output (& $module { param($v) ConvertTo-WtCanonicalJson (Copy-WtJsonValue $v) } $Result)
    }
    elseif ($Fields) { & $Fields }
    if ($Ok) { Write-Output ($token + '_OK'); exit 0 }
    Write-Output ('{0}_FAIL:{1}' -f $token, $Code); exit 1
}

function Get-Time { if ($VerificationTime) { return $VerificationTime } return (& $module { Get-WtUtcNow }) }

try {
    switch ($name) {
        'help' { Get-Help $PSCommandPath -Detailed | Out-String | Write-Output; exit 0 }
        'version' {
            $version = $module.Version.ToString()
            Complete-Command -Ok $true -Result ([ordered]@{ version = $version }) -Fields { Write-Field 'version' $version }
        }
        'init' {
            $r = Initialize-WtTrust -Root $Root -CreatedUtc (Get-Time)
            $result = [ordered]@{ principal = $r.Principal; key_id = $r.KeyId; node_id = $r.NodeId; created_key = $r.CreatedKey; public_key = $r.PublicKey }
            Complete-Command -Ok $true -Result $result -Fields { foreach ($k in $result.PSBase.Keys) { Write-Field $k $result[$k] } }
        }
        'enroll' {
            if ($FromBundle) {
                if (-not $Principal) { throw (& $module { New-WtFailure 'USAGE' 'enroll -FromBundle needs -Principal' }) }
                $arguments = @{ Root = $Root; BundlePath = $FromBundle; Principal = $Principal; KeyId = $KeyId; BundleRoot = $BundleRoot; NeverLostReceipt = $NeverLostReceipt; AllowTestKey = $AllowTestKey }
                if ($Namespace.Count -gt 0) { $arguments['Namespace'] = $Namespace }
                $r = Import-WtNeverLostProducer @arguments
                $result = [ordered]@{
                    principal = $r.Principal; bundle_sha256 = $r.BundleSha256; integration_receipt_sha256 = $r.IntegrationReceiptSha256
                    keys = @($r.Enrolled | ForEach-Object { [ordered]@{ key_id = $_.KeyId; changed = $_.Changed } })
                }
                Complete-Command -Ok $true -Result $result -Fields {
                    Write-Field 'principal' $r.Principal
                    foreach ($k in $r.Enrolled) { Write-Field 'key' ('{0} changed={1}' -f $k.KeyId, $k.Changed) }
                    Write-Field 'bundle_sha256' $r.BundleSha256
                    Write-Field 'integration_receipt_sha256' $r.IntegrationReceiptSha256
                }
            }
            if (-not $Principal -or -not $KeyId -or -not $PublicKey) { throw (& $module { New-WtFailure 'USAGE' 'enroll needs -Principal, -KeyId and -PublicKey (or -FromBundle)' }) }
            $arguments = @{ Root = $Root; Principal = $Principal; KeyId = $KeyId; PublicKey = $PublicKey; AllowTestKey = $AllowTestKey }
            if ($Namespace.Count -gt 0) { $arguments['Namespace'] = $Namespace }
            $r = Register-WtProducer @arguments
            $result = [ordered]@{ principal = $r.Principal; key_id = $r.KeyId; changed = $r.Changed }
            Complete-Command -Ok $true -Result $result -Fields { foreach ($k in $result.PSBase.Keys) { Write-Field $k $result[$k] } }
        }
        'trust' {
            $r = Get-WtTrust -Root $Root
            $principals = @($r.Principals | ForEach-Object { [ordered]@{ principal = $_.Principal; key_id = $_.KeyId; namespaces = @($_.Namespaces) } })
            $result = [ordered]@{ allowed_signers_derived = $r.AllowedSignersDerived; principals = $principals }
            $code = $(if ($r.AllowedSignersDerived) { 'OK' } else { 'ALLOWED_SIGNERS_NOT_DERIVED' })
            Complete-Command -Ok $r.AllowedSignersDerived -Code $code -Result $result -Fields {
                Write-Field 'allowed_signers_derived' $r.AllowedSignersDerived
                foreach ($p in $r.Principals) { Write-Field 'principal' ('{0} key={1} namespaces={2}' -f $p.Principal, $p.KeyId, (@($p.Namespaces) -join ',')) }
            }
        }
        'verify-packet' {
            if (-not $Path) { throw (& $module { New-WtFailure 'USAGE' 'verify-packet <path>' }) }
            $r = Test-WtPacket $Path
            $result = [ordered]@{ valid = $r.Valid; code = $r.Code; packet_id = $r.PacketId }
            Complete-Command -Ok $r.Valid -Code $r.Code -Result $result -Fields { Write-Field 'packet_id' $r.PacketId; Write-Field 'code' $r.Code }
        }
        'verify-telemetry' {
            if (-not $Path) { throw (& $module { New-WtFailure 'USAGE' 'verify-telemetry <path>' }) }
            $trust = Get-WtTrust -Root $Root
            $r = Test-WtTelemetryPacket -Path $Path -TrustBundle $trust.Bundle
            $result = [ordered]@{
                valid = $r.Valid; code = $r.Code; stage = $r.Stage; signer_verified = $r.SignerVerified; packet_id = $r.PacketId
                event_type = $r.EventType; producer = $r.Producer; device_id = $r.DeviceId; producer_time = $r.ProducerTime; seq = $r.Seq
            }
            Complete-Command -Ok $r.Valid -Code $r.Code -Result $result -Fields { foreach ($k in $result.PSBase.Keys) { Write-Field $k $result[$k] } }
        }
        'ingest' {
            $r = Invoke-WtIngest -Root $Root -VerificationTime (Get-Time)
            $result = [ordered]@{
                processed = $r.Processed; accepted = $r.Accepted; rejected = $r.Rejected; receipt_head = $r.ReceiptHead; receipt_count = $r.ReceiptCount
                checkpoint_hash = $r.CheckpointHash; outbox_packet_id = $r.OutboxPacketId; pledge_hash = $r.PledgeHash
                results = @($r.Results | ForEach-Object { [ordered]@{ packet_ref = $_.PacketRef; code = $_.Code; routed_to = $_.RoutedTo } })
            }
            Complete-Command -Ok $true -Result $result -Fields {
                foreach ($k in @('processed', 'accepted', 'rejected', 'receipt_count', 'receipt_head', 'checkpoint_hash', 'outbox_packet_id', 'pledge_hash')) { Write-Field $k $result[$k] }
                foreach ($item in $r.Results) { Write-Field 'packet' ('{0} {1} -> {2}' -f $item.PacketRef, $item.Code, $item.RoutedTo) }
            }
        }
        'ledger' {
            $r = Test-WtLedger -Root $Root
            $counts = [ordered]@{}
            if ($r.Ledgers) {
                foreach ($ledger in @('Receipts', 'Alerts', 'Checkpoints', 'Pledges')) { $counts[$ledger.ToLowerInvariant()] = $r.Ledgers.$ledger.Count }
                $counts['integration_receipts'] = [long](@($r.Ledgers.Integrations | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum
                $counts['integration_witnesses'] = $r.Ledgers.IntegrationWitness.Count
            }
            $result = [ordered]@{ valid = $r.Valid; code = $r.Code; counts = $counts; warnings = @($r.Warnings) }
            Complete-Command -Ok $r.Valid -Code $r.Code -Result $result -Fields {
                foreach ($k in $counts.PSBase.Keys) { Write-Field $k $counts[$k] }
                foreach ($w in $r.Warnings) { Write-Field 'warning' $w }
            }
        }
        'doctor' {
            $r = Invoke-WtDoctor -Root $Root -VerificationTime (Get-Time) -Publish:$Publish
            $failed = @($r.Checks | Where-Object { -not $_['ok'] } | ForEach-Object { $_['code'] })
            $code = $(if ($r.HealthOk) { 'OK' } else { [string]$failed[0] })
            Complete-Command -Ok $r.HealthOk -Code $code -Result $r.Report -Fields {
                foreach ($check in $r.Checks) { Write-Field $check['name'] ('{0} {1}' -f $check['code'], $check['detail']) }
                Write-Field 'inbox_pending' $r.InboxPending
            }
        }
        'integrations' {
            $r = Test-WtIntegrations -Root $Root
            $published = $null
            if ($r.Valid -and $Witness) {
                $published = Publish-WtIntegrationReceipts -Root $Root -VerificationTime (Get-Time)
                $r = Test-WtIntegrations -Root $Root
            }
            $result = [ordered]@{
                valid = $r.Valid; code = $r.Code
                integrations = @($r.Integrations | ForEach-Object { [ordered]@{ integration = $_.Integration; count = $_.Count; head = $_.Head } })
                witness_count = $(if ($r.Witness) { $r.Witness.Count } else { 0 })
                witness_packet_id = $(if ($published) { $published.PacketId } else { '' })
                warnings = @($r.Warnings)
            }
            Complete-Command -Ok $r.Valid -Code $r.Code -Result $result -Fields {
                foreach ($i in $r.Integrations) { Write-Field 'integration' ('{0} count={1} head={2}' -f $i.Integration, $i.Count, $i.Head) }
                Write-Field 'witness_count' $result['witness_count']
                if ($published) { Write-Field 'witness_packet_id' $published.PacketId }
                foreach ($w in $r.Warnings) { Write-Field 'warning' $w }
                if (-not $r.Valid) { Write-Field 'detail' $r.Detail }
            }
        }
        'index' {
            $written = Export-WtEvidenceIndex -Root $Root -GeneratedUtc (Get-Time)
            Complete-Command -Ok $true -Result ([ordered]@{ path = 'runtime/evidence_index.json' }) -Fields { Write-Field 'path' $written }
        }
        default {
            $token = 'WATCHTOWER_CLI'
            Write-Output ('error=unknown command "{0}" (try: help)' -f $Command)
            Complete-Command -Ok $false -Code 'UNKNOWN_COMMAND'
        }
    }
}
catch {
    $code = & $module { param($e) Get-WtFailureCode $e } $_
    Write-Output ('error=' + $_.Exception.Message)
    Write-Output ('{0}_FAIL:{1}' -f $token, $code)
    exit 1
}
