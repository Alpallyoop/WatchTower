# Failure model.
#
# Every WatchTower failure is fail-closed and carries a stable, machine-readable
# code. Callers branch on the code, never on message text:
#
#   throw (New-WtFailure 'PACKET_ID_MISMATCH' $detail)
#     -> message  "WT_FAIL:PACKET_ID_MISMATCH: <detail>"
#     -> Exception.Data['wt_code'] = 'PACKET_ID_MISMATCH'

function New-WtFailure {
    [OutputType([System.Exception])]
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Z][A-Z0-9_]*$')][string]$Code,
        [AllowEmptyString()][AllowNull()][string]$Detail = ''
    )
    $message = 'WT_FAIL:' + $Code
    if ($Detail) { $message = $message + ': ' + $Detail }
    $exception = New-Object System.InvalidOperationException($message)
    $exception.Data['wt_code'] = $Code
    return $exception
}

function Get-WtFailureCode {
    # The stable code of an ErrorRecord or Exception; 'UNHANDLED' for anything
    # that did not originate from New-WtFailure.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$ErrorObject)
    $exception = if ($ErrorObject -is [System.Management.Automation.ErrorRecord]) { $ErrorObject.Exception } else { $ErrorObject }
    while ($null -ne $exception) {
        if ($exception.Data -and $exception.Data.Contains('wt_code')) { return [string]$exception.Data['wt_code'] }
        $match = [regex]::Match([string]$exception.Message, 'WT_FAIL:([A-Z][A-Z0-9_]*)')
        if ($match.Success) { return $match.Groups[1].Value }
        $exception = $exception.InnerException
    }
    return 'UNHANDLED'
}

function Get-WtFailureMessage {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$ErrorObject)
    if ($ErrorObject -is [System.Management.Automation.ErrorRecord]) { return [string]$ErrorObject.Exception.Message }
    return [string]$ErrorObject.Message
}
