@{
    RootModule           = 'WatchTower.psm1'
    ModuleVersion        = '2.0.0'
    GUID                 = 'c4604112-95b4-5143-80e3-804b378442c7'
    Author               = 'Alec Maiatico'
    CompanyName          = 'ScrappyHub'
    Copyright            = '(c) ScrappyHub.'
    Description          = 'WatchTower: deterministic verifier and telemetry receipt authority (Constellation service "watchtower"). Verifies signed PCv1 telemetry packets against a pinned NeverLost trust bundle and issues hash-chained verifier receipts, alert evidence, checkpoint seals, device pledges and NFL receipt packets.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Export-WtEvidenceIndex'
        'Get-WtTrust'
        'Initialize-WtTrust'
        'Invoke-WtDoctor'
        'Invoke-WtIngest'
        'New-WtPacket'
        'Register-WtProducer'
        'Test-WtLedger'
        'Test-WtPacket'
        'Test-WtTelemetryPacket'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Constellation', 'verifier', 'telemetry', 'PCv1', 'NeverLost', 'receipts')
            ProjectUri   = 'https://github.com/ScrappyHub/WatchTower'
            ReleaseNotes = 'v2.0.0: canonical verifier per the Constellation registry (see docs/canonical/SPEC.md).'
        }
    }
}
