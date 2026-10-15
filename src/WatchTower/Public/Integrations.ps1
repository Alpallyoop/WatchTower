function Test-WtIntegrations {
    <#
    .SYNOPSIS
        Re-verifies WatchTower's Constellation integration receipts from bytes.
    .DESCRIPTION
        Every ledger under proofs/integrations (constellation.integration.receipt.v1: schema rules,
        exact serialization, prev_sha256 chain) and the NFL witness ledger with the outbox packets it
        names. Read-only. Returns Valid, Code, Detail, Integrations (per ledger: Integration, Count,
        Head), Witness (Count, Head) and Warnings (for example receipts not yet witnessed).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$Root)
    $report = [pscustomobject]@{ Valid = $false; Code = ''; Detail = ''; Integrations = @(); Witness = $null; Warnings = (New-Object System.Collections.ArrayList) }
    try {
        $layout = Get-WtLayout $Root
        $bundle = Read-WtTrustBundle $layout.TrustBundle -Root $layout.Root
        $result = Test-WtIntegrationEvidence -Layout $layout -Warnings $report.Warnings -Bundle $bundle
        $report.Integrations = $result.Integrations
        $report.Witness = $result.Witness
        $report.Valid = $true
        $report.Code = 'OK'
    }
    catch {
        $report.Code = Get-WtFailureCode $_
        $report.Detail = Get-WtFailureMessage $_
    }
    return $report
}

function Publish-WtIntegrationReceipts {
    <#
    .SYNOPSIS
        Hands every not-yet-witnessed integration receipt to NFL through packets/outbox.
    .DESCRIPTION
        Builds one PCv1 Option A packet (watchtower.integration_witness.v1) carrying the new receipt
        lines byte-identical, signs its manifest (packet/envelope), and records it in the witness
        ledger. Every ingest run does this too; this command exists for receipts written outside an
        ingest (enroll -FromBundle). Returns $null when there is nothing to witness.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory = $true)][string]$Root, [string]$VerificationTime = (Get-WtUtcNow))
    [void](ConvertFrom-WtUtcTime $VerificationTime 'VerificationTime')
    $layout = Get-WtLayout $Root
    $bundle = Read-WtTrustBundle $layout.TrustBundle -Root $layout.Root
    $authority = Get-WtAuthority -Layout $layout -Bundle $bundle
    # Same writer lock as ingest: two witness writers must never fork the witness ledger.
    $lock = Enter-WtIngestLock $layout
    try {
        [void](Test-WtIntegrationEvidence -Layout $layout -Warnings (New-Object System.Collections.ArrayList) -Bundle $bundle)
        return (Publish-WtIntegrationWitness -Layout $layout -Authority $authority -VerifiedUtc $VerificationTime)
    }
    finally { Exit-WtIngestLock $lock }
}
