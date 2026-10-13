# Native process execution and OpenSSH signatures (ssh-keygen -Y).
#
# Arguments are passed as an exact argv: ProcessStartInfo.ArgumentList on
# .NET (PowerShell 7), MSVCRT-correct quoting on .NET Framework (5.1). This is
# what makes `ssh-keygen -N ""` work on Windows PowerShell 5.1, where the
# empty argument used to be dropped ("Too many arguments").
# Message bytes go to stdin directly from the file - never through a
# PowerShell pipeline, which would re-encode text and append CRLF.

$script:WtHasArgumentList = $null -ne [System.Diagnostics.ProcessStartInfo].GetProperty('ArgumentList')

function ConvertTo-WtWindowsArgument {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Argument)
    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') { return $Argument }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($ch in $Argument.ToCharArray()) {
        if ($ch -eq '\') { $backslashes++; continue }
        if ($ch -eq '"') { [void]$builder.Append('\' * (2 * $backslashes + 1)); [void]$builder.Append('"') }
        else { if ($backslashes -gt 0) { [void]$builder.Append('\' * $backslashes) }; [void]$builder.Append($ch) }
        $backslashes = 0
    }
    if ($backslashes -gt 0) { [void]$builder.Append('\' * (2 * $backslashes)) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-WtNative {
    # stdin is always redirected and closed, so a tool can never block on a prompt.
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$ArgumentList,
        [string]$StdinPath = '',
        [int]$TimeoutMilliseconds = 120000
    )
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $FilePath
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    if ($script:WtHasArgumentList) { foreach ($argument in $ArgumentList) { [void]$info.ArgumentList.Add($argument) } }
    else { $info.Arguments = (@($ArgumentList | ForEach-Object { ConvertTo-WtWindowsArgument $_ }) -join ' ') }
    # Windows PowerShell 5.1 (.NET Framework) wraps stdin in a writer that uses the console
    # input encoding; with code page 65001 that encoding writes a UTF-8 BOM into the stream,
    # which ssh-keygen -Y verify would hash as part of the message. Use a BOM-free encoding
    # while the process starts, and refuse to feed a message through a BOM-writing stream.
    $restoreEncoding = $null
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        try {
            if ([Console]::InputEncoding.GetPreamble().Length -gt 0) {
                $restoreEncoding = [Console]::InputEncoding
                [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
            }
        }
        catch { Write-Verbose 'no console input encoding to adjust' }
    }
    try { $process = [System.Diagnostics.Process]::Start($info) }
    finally { if ($null -ne $restoreEncoding) { try { [Console]::InputEncoding = $restoreEncoding } catch { Write-Verbose 'console encoding not restored' } } }
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($StdinPath) {
            if ($process.StandardInput.Encoding.GetPreamble().Length -gt 0) {
                try { $process.Kill() } catch { Write-Verbose 'process already exited' }
                throw (New-WtFailure 'NATIVE_STDIN_BOM' 'the console input encoding would prepend a byte-order mark')
            }
            $bytes = Read-WtBytes $StdinPath
            # A tool may exit before reading all of stdin (for example on a malformed
            # signature); its exit code decides the outcome, not the broken pipe.
            try {
                $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
                $process.StandardInput.BaseStream.Flush()
            }
            catch [System.IO.IOException] { Write-Verbose 'stdin closed early by the tool' }
        }
        try { $process.StandardInput.Close() } catch [System.IO.IOException] { Write-Verbose 'stdin already closed' }
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            try { $process.Kill() } catch { Write-Verbose 'process already exited' }
            throw (New-WtFailure 'NATIVE_TIMEOUT' $FilePath)
        }
        $process.WaitForExit()
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout.Result; Stderr = $stderr.Result }
    }
    finally { $process.Dispose() }
}

function Get-WtSshKeygenPath {
    [OutputType([string])]
    param()
    $command = Get-Command ssh-keygen -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { throw (New-WtFailure 'SSH_KEYGEN_NOT_FOUND') }
    return $command.Source
}

function New-WtSshKey {
    # Unencrypted ed25519 key pair; refuses to overwrite.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Comment)
    if ([System.IO.File]::Exists($Path) -or [System.IO.File]::Exists($Path + '.pub')) { throw (New-WtFailure 'KEY_ALREADY_EXISTS' $Path) }
    New-WtDirectory ([System.IO.Path]::GetDirectoryName((Resolve-WtFullPath $Path)))
    $result = Invoke-WtNative -FilePath (Get-WtSshKeygenPath) -ArgumentList @('-q', '-t', 'ed25519', '-N', '', '-C', $Comment, '-f', $Path)
    if ($result.ExitCode -ne 0 -or -not [System.IO.File]::Exists($Path) -or -not [System.IO.File]::Exists($Path + '.pub')) {
        throw (New-WtFailure 'KEYGEN_FAILED' $result.Stderr.Trim())
    }
}

function ConvertTo-WtPublicKey {
    # Canonical 'ssh-ed25519 <base64>' (comment stripped), NeverLost rule.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line)
    $parts = @($Line.Trim() -split '\s+')
    if ($parts.Count -lt 2 -or $parts[0] -cne 'ssh-ed25519' -or $parts[1] -cnotmatch '^[A-Za-z0-9+/]+={0,2}$') { throw (New-WtFailure 'PUBKEY_FORMAT') }
    return ($parts[0] + ' ' + $parts[1])
}

function New-WtSignature {
    # Detached SSHSIG over the exact bytes of $MessagePath, written to $SignaturePath.
    # Signs a private copy because ssh-keygen prompts when a .sig already exists.
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$Namespace,
        [Parameter(Mandatory = $true)][string]$MessagePath,
        [Parameter(Mandatory = $true)][string]$SignaturePath
    )
    $work = New-WtTempDirectory 'wtsign'
    try {
        $message = Join-Path $work 'message'
        [System.IO.File]::WriteAllBytes($message, (Read-WtBytes $MessagePath))
        $result = Invoke-WtNative -FilePath (Get-WtSshKeygenPath) -ArgumentList @('-Y', 'sign', '-f', $KeyPath, '-n', $Namespace, $message)
        $signature = $message + '.sig'
        if ($result.ExitCode -ne 0 -or -not [System.IO.File]::Exists($signature)) { throw (New-WtFailure 'SIGN_FAILED' $result.Stderr.Trim()) }
        Write-WtBytes -Path $SignaturePath -Bytes ([System.IO.File]::ReadAllBytes($signature))
    }
    finally { Remove-WtTree $work }
}

function Assert-WtArmoredSignature {
    param([Parameter(Mandatory = $true)][string]$Path)
    $text = Read-WtText $Path
    if (-not $text.StartsWith("-----BEGIN SSH SIGNATURE-----`n") -or -not $text.TrimEnd("`n").EndsWith('-----END SSH SIGNATURE-----')) {
        throw (New-WtFailure 'SIG_NOT_ARMORED' $Path)
    }
}

function Test-WtSignature {
    # $true only when ssh-keygen reports a Good signature for exactly this
    # principal and namespace against the given allowed_signers file.
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$AllowedSignersPath,
        [Parameter(Mandatory = $true)][string]$Principal,
        [Parameter(Mandatory = $true)][string]$Namespace,
        [Parameter(Mandatory = $true)][string]$SignaturePath,
        [Parameter(Mandatory = $true)][string]$MessagePath
    )
    Assert-WtArmoredSignature $SignaturePath
    $result = Invoke-WtNative -FilePath (Get-WtSshKeygenPath) -StdinPath $MessagePath -ArgumentList @(
        '-Y', 'verify', '-f', $AllowedSignersPath, '-I', $Principal, '-n', $Namespace, '-s', $SignaturePath)
    if ($result.ExitCode -ne 0) { return $false }
    return ([string]$result.Stdout).Contains(('Good "{0}" signature for {1} ' -f $Namespace, $Principal))
}

function Test-WtSshSigSupport {
    # Proves this host's ssh-keygen can sign and verify SSHSIG (OpenSSH 8.1+): a throwaway
    # key signs a message, the signature verifies, and a changed message does not. Windows
    # 10 / Server 2019 ship OpenSSH 7.7, which has no -Y sign/verify.
    [OutputType([string])]
    param()
    $keygen = Get-WtSshKeygenPath
    $directory = New-WtTempDirectory 'wt_sshsig_probe'
    try {
        $key = Join-Path $directory 'probe_ed25519'
        $message = Join-Path $directory 'message.txt'
        $signature = Join-Path $directory 'message.txt.sig'
        $signers = Join-Path $directory 'allowed_signers'
        try {
            New-WtSshKey -Path $key -Comment 'watchtower-sshsig-probe'
            Write-WtText -Path $message -Text 'watchtower sshsig probe'
            New-WtSignature -KeyPath $key -Namespace 'watchtower/probe' -MessagePath $message -SignaturePath $signature
        }
        catch { throw (New-WtFailure 'SSH_KEYGEN_NO_SSHSIG' ('{0}: {1}' -f $keygen, (Get-WtFailureCode $_))) }
        Write-WtText -Path $signers -Text ('probe namespaces="watchtower/probe" ' + (ConvertTo-WtPublicKey (Read-WtText ($key + '.pub'))))
        if (-not (Test-WtSignature -AllowedSignersPath $signers -Principal 'probe' -Namespace 'watchtower/probe' -SignaturePath $signature -MessagePath $message)) {
            throw (New-WtFailure 'SSH_KEYGEN_NO_SSHSIG' ($keygen + ': a valid signature did not verify'))
        }
        Write-WtText -Path $message -Text 'watchtower sshsig probe, changed'
        if (Test-WtSignature -AllowedSignersPath $signers -Principal 'probe' -Namespace 'watchtower/probe' -SignaturePath $signature -MessagePath $message) {
            throw (New-WtFailure 'SSH_KEYGEN_NO_SSHSIG' ($keygen + ': a changed message verified'))
        }
        return $keygen
    }
    finally { Remove-WtTree $directory }
}
