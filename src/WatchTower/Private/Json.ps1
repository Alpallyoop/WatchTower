# Strict JSON parser and canonical JSON writer.
#
# ConvertFrom-Json / ConvertTo-Json are never used for anything that is hashed,
# signed or compared: PowerShell 7 coerces ISO-8601 strings into DateTime, and
# 5.1 and 7 escape characters differently, so round trips are not byte-stable.
#
# Parser output: object -> OrderedDictionary (ordinal, case-sensitive keys),
# array -> ArrayList, string, [long], [bool], $null.
# Rejected: fractions/exponents, duplicate keys, trailing data, invalid escapes,
# raw control characters, lone surrogates, nesting deeper than 64.
#
# Canonical form (docs/canonical-json.md; identical to NeverLost NL-JsonCanon):
# keys sorted ordinally, compact separators, integers only, escapes only
# " \ \b \t \n \f \r and other code points below 0x20 as \u00xx; everything else
# is raw UTF-8. Canonical files end with exactly one LF.

$script:WtJsonMaxDepth = 64
$script:WtJsonInvariant = [System.Globalization.CultureInfo]::InvariantCulture
$script:WtJsonStopChars = [char[]](@([char]'"', [char]'\') + @(0..31 | ForEach-Object { [char]$_ }))
$script:WtJsonNumberPattern = New-Object System.Text.RegularExpressions.Regex(
    '\G-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)

function New-WtObject {
    # An empty JSON object with ordinal (case-sensitive) keys.
    param()
    return , (New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::Ordinal))
}

#region Parser

function Skip-WtJsonWhitespace {
    param([hashtable]$State)
    $text = $State.Text; $index = $State.Index; $length = $State.Length
    while ($index -lt $length) {
        $c = $text[$index]
        if ($c -eq ' ' -or $c -eq "`t" -or $c -eq "`n" -or $c -eq "`r") { $index++ } else { break }
    }
    $State.Index = $index
}

function Read-WtJsonHex4 {
    param([string]$Text, [int]$Offset)
    if ($Offset + 4 -gt $Text.Length) { throw (New-WtFailure 'JSON_BAD_ESCAPE' ('offset {0}' -f $Offset)) }
    $hex = $Text.Substring($Offset, 4)
    if ($hex -notmatch '^[0-9a-fA-F]{4}$') { throw (New-WtFailure 'JSON_BAD_ESCAPE' ('offset {0}' -f $Offset)) }
    return [Convert]::ToInt32($hex, 16)
}

function Read-WtJsonString {
    param([hashtable]$State)
    $text = $State.Text; $length = $State.Length; $index = $State.Index + 1
    $builder = New-Object System.Text.StringBuilder
    while ($true) {
        $stop = if ($index -lt $length) { $text.IndexOfAny($script:WtJsonStopChars, $index) } else { -1 }
        if ($stop -lt 0) { throw (New-WtFailure 'JSON_UNTERMINATED_STRING') }
        if ($stop -gt $index) { [void]$builder.Append($text, $index, $stop - $index) }
        $c = $text[$stop]
        if ($c -eq '"') { $State.Index = $stop + 1; return $builder.ToString() }
        if ([int]$c -lt 32) { throw (New-WtFailure 'JSON_CONTROL_CHAR_IN_STRING' ('offset {0}' -f $stop)) }
        if ($stop + 1 -ge $length) { throw (New-WtFailure 'JSON_BAD_ESCAPE' ('offset {0}' -f $stop)) }
        $escape = [string]$text[$stop + 1]
        $index = $stop + 2
        switch -CaseSensitive ($escape) {
            '"' { [void]$builder.Append('"') }
            '\' { [void]$builder.Append('\') }
            '/' { [void]$builder.Append('/') }
            'b' { [void]$builder.Append([char]8) }
            'f' { [void]$builder.Append([char]12) }
            'n' { [void]$builder.Append([char]10) }
            'r' { [void]$builder.Append([char]13) }
            't' { [void]$builder.Append([char]9) }
            'u' {
                $code = Read-WtJsonHex4 -Text $text -Offset ($stop + 2)
                $index = $stop + 6
                if ($code -ge 0xD800 -and $code -le 0xDBFF) {
                    if ($index + 1 -ge $length -or $text[$index] -ne '\' -or $text[$index + 1] -ne 'u') {
                        throw (New-WtFailure 'JSON_LONE_SURROGATE' ('offset {0}' -f $stop))
                    }
                    $low = Read-WtJsonHex4 -Text $text -Offset ($index + 2)
                    if ($low -lt 0xDC00 -or $low -gt 0xDFFF) { throw (New-WtFailure 'JSON_LONE_SURROGATE' ('offset {0}' -f $index)) }
                    [void]$builder.Append([char]$code).Append([char]$low)
                    $index += 6
                }
                elseif ($code -ge 0xDC00 -and $code -le 0xDFFF) { throw (New-WtFailure 'JSON_LONE_SURROGATE' ('offset {0}' -f $stop)) }
                else { [void]$builder.Append([char]$code) }
            }
            default { throw (New-WtFailure 'JSON_BAD_ESCAPE' ('\{0} at offset {1}' -f $escape, $stop)) }
        }
    }
}

function Read-WtJsonValue {
    param([hashtable]$State, [int]$Depth)
    if ($Depth -gt $script:WtJsonMaxDepth) { throw (New-WtFailure 'JSON_TOO_DEEP') }
    Skip-WtJsonWhitespace $State
    if ($State.Index -ge $State.Length) { throw (New-WtFailure 'JSON_UNEXPECTED_END') }
    $text = $State.Text
    $c = $text[$State.Index]

    if ($c -eq '{') {
        $State.Index++
        $object = New-WtObject
        Skip-WtJsonWhitespace $State
        if ($State.Index -lt $State.Length -and $text[$State.Index] -eq '}') { $State.Index++; return , $object }
        while ($true) {
            Skip-WtJsonWhitespace $State
            if ($State.Index -ge $State.Length -or $text[$State.Index] -ne '"') { throw (New-WtFailure 'JSON_EXPECTED_KEY' ('offset {0}' -f $State.Index)) }
            $key = Read-WtJsonString $State
            Skip-WtJsonWhitespace $State
            if ($State.Index -ge $State.Length -or $text[$State.Index] -ne ':') { throw (New-WtFailure 'JSON_EXPECTED_COLON' ('offset {0}' -f $State.Index)) }
            $State.Index++
            $value = Read-WtJsonValue $State ($Depth + 1)
            if ($object.Contains($key)) { throw (New-WtFailure 'JSON_DUPLICATE_KEY' $key) }
            $object.Add($key, $value)
            Skip-WtJsonWhitespace $State
            if ($State.Index -ge $State.Length) { throw (New-WtFailure 'JSON_UNEXPECTED_END') }
            $next = $text[$State.Index]
            $State.Index++
            if ($next -eq ',') { continue }
            if ($next -eq '}') { return , $object }
            throw (New-WtFailure 'JSON_EXPECTED_COMMA_OR_BRACE' ('offset {0}' -f ($State.Index - 1)))
        }
    }

    if ($c -eq '[') {
        $State.Index++
        $array = New-Object System.Collections.ArrayList
        Skip-WtJsonWhitespace $State
        if ($State.Index -lt $State.Length -and $text[$State.Index] -eq ']') { $State.Index++; return , $array }
        while ($true) {
            [void]$array.Add((Read-WtJsonValue $State ($Depth + 1)))
            Skip-WtJsonWhitespace $State
            if ($State.Index -ge $State.Length) { throw (New-WtFailure 'JSON_UNEXPECTED_END') }
            $next = $text[$State.Index]
            $State.Index++
            if ($next -eq ',') { continue }
            if ($next -eq ']') { return , $array }
            throw (New-WtFailure 'JSON_EXPECTED_COMMA_OR_BRACKET' ('offset {0}' -f ($State.Index - 1)))
        }
    }

    if ($c -eq '"') { return (Read-WtJsonString $State) }

    foreach ($literal in @(@('true', $true), @('false', $false), @('null', $null))) {
        $word = [string]$literal[0]
        if ($c -ne $word[0]) { continue }
        if ($State.Index + $word.Length -le $State.Length -and $text.Substring($State.Index, $word.Length) -ceq $word) {
            $State.Index += $word.Length
            return $literal[1]
        }
        throw (New-WtFailure 'JSON_BAD_LITERAL' ('offset {0}' -f $State.Index))
    }

    if ($c -eq '-' -or ($c -ge '0' -and $c -le '9')) {
        $match = $script:WtJsonNumberPattern.Match($text, $State.Index)
        if (-not $match.Success -or $match.Length -eq 0) { throw (New-WtFailure 'JSON_BAD_NUMBER' ('offset {0}' -f $State.Index)) }
        if ($match.Groups[2].Success -or $match.Groups[3].Success) { throw (New-WtFailure 'JSON_FLOAT_FORBIDDEN' ('offset {0}' -f $State.Index)) }
        $State.Index += $match.Length
        $number = [long]0
        if (-not [long]::TryParse($match.Value, [System.Globalization.NumberStyles]::AllowLeadingSign, $script:WtJsonInvariant, [ref]$number)) {
            throw (New-WtFailure 'JSON_INT_RANGE' $match.Value)
        }
        return $number
    }

    throw (New-WtFailure 'JSON_UNEXPECTED_CHAR' ('offset {0}' -f $State.Index))
}

function ConvertFrom-WtJson {
    # Strictly parses JSON text into ordered, case-sensitive structures.
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $state = @{ Text = $Text; Index = 0; Length = $Text.Length }
    $value = Read-WtJsonValue $state 0
    Skip-WtJsonWhitespace $state
    if ($state.Index -ne $state.Length) { throw (New-WtFailure 'JSON_TRAILING_DATA' ('offset {0}' -f $state.Index)) }
    return , $value
}

#endregion

#region Canonical writer

function Add-WtCanonicalString {
    param([System.Text.StringBuilder]$Builder, [string]$Value)
    [void]$Builder.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 34) { [void]$Builder.Append('\"') }
        elseif ($code -eq 92) { [void]$Builder.Append('\\') }
        elseif ($code -eq 8) { [void]$Builder.Append('\b') }
        elseif ($code -eq 9) { [void]$Builder.Append('\t') }
        elseif ($code -eq 10) { [void]$Builder.Append('\n') }
        elseif ($code -eq 12) { [void]$Builder.Append('\f') }
        elseif ($code -eq 13) { [void]$Builder.Append('\r') }
        elseif ($code -lt 32) { [void]$Builder.Append('\u').Append($code.ToString('x4', $script:WtJsonInvariant)) }
        else { [void]$Builder.Append($ch) }
    }
    [void]$Builder.Append('"')
}

function Add-WtCanonicalValue {
    param([System.Text.StringBuilder]$Builder, $Value, [int]$Depth)
    if ($Depth -gt $script:WtJsonMaxDepth) { throw (New-WtFailure 'CANON_TOO_DEEP') }
    if ($null -eq $Value) { [void]$Builder.Append('null'); return }
    if ($Value -is [System.Management.Automation.PSObject]) {
        $base = $Value.PSObject.BaseObject
        if ($base -isnot [System.Management.Automation.PSCustomObject]) { $Value = $base }
    }

    if ($Value -is [bool]) {
        if ($Value) { [void]$Builder.Append('true') } else { [void]$Builder.Append('false') }
        return
    }
    if ($Value -is [string]) { Add-WtCanonicalString $Builder $Value; return }
    if ($Value -is [long] -or $Value -is [int] -or $Value -is [int16] -or $Value -is [byte] -or
        $Value -is [sbyte] -or $Value -is [uint16] -or $Value -is [uint32]) {
        [void]$Builder.Append(([long]$Value).ToString($script:WtJsonInvariant))
        return
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal] -or $Value -is [uint64]) {
        throw (New-WtFailure 'JSON_FLOAT_FORBIDDEN' ([string]$Value))
    }
    if ($Value -is [datetime] -or $Value -is [DateTimeOffset]) { throw (New-WtFailure 'JSON_DATETIME_FORBIDDEN') }
    if ($Value -is [char]) { throw (New-WtFailure 'JSON_UNSUPPORTED_TYPE' 'char') }

    if ($Value -is [System.Collections.IDictionary]) {
        # PSBase: on a dictionary holding an entry named "Keys", PowerShell's $d.Keys returns
        # that entry's value. Parsed input is attacker-controlled, so never use $d.Keys.
        $keys = New-Object System.Collections.Generic.List[string]
        foreach ($key in $Value.PSBase.Keys) {
            if ($key -isnot [string]) { throw (New-WtFailure 'JSON_NON_STRING_KEY') }
            $keys.Add($key)
        }
        $sorted = $keys.ToArray()
        [Array]::Sort($sorted, [System.StringComparer]::Ordinal)
        [void]$Builder.Append('{')
        for ($i = 0; $i -lt $sorted.Length; $i++) {
            if ($i -gt 0) {
                # A case-insensitive Hashtable cannot hold these, but a custom IDictionary could.
                if ([string]::Equals($sorted[$i], $sorted[$i - 1], [StringComparison]::Ordinal)) { throw (New-WtFailure 'JSON_DUPLICATE_KEY' $sorted[$i]) }
                [void]$Builder.Append(',')
            }
            Add-WtCanonicalString $Builder $sorted[$i]
            [void]$Builder.Append(':')
            Add-WtCanonicalValue $Builder $Value[$sorted[$i]] ($Depth + 1)
        }
        [void]$Builder.Append('}')
        return
    }

    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $object = New-WtObject
        foreach ($property in $Value.PSObject.Properties) { $object.Add($property.Name, $property.Value) }
        Add-WtCanonicalValue $Builder $object $Depth
        return
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        [void]$Builder.Append('[')
        $first = $true
        foreach ($item in $Value) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            Add-WtCanonicalValue $Builder $item ($Depth + 1)
        }
        [void]$Builder.Append(']')
        return
    }

    throw (New-WtFailure 'JSON_UNSUPPORTED_TYPE' $Value.GetType().FullName)
}

function ConvertTo-WtCanonicalJson {
    # Canonical JSON text, without a trailing newline.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowNull()]$Value)
    $builder = New-Object System.Text.StringBuilder
    Add-WtCanonicalValue $builder $Value 0
    return $builder.ToString()
}

function Get-WtCanonicalHash {
    # sha256(canonical_json(value) + LF): the ledger.md / LSS / NeverLost rule.
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowNull()]$Value)
    return Get-WtSha256 -Text ((ConvertTo-WtCanonicalJson $Value) + "`n")
}

function Copy-WtJsonValue {
    # Deep copy through canonical JSON; also proves the value is canonicalisable.
    param([Parameter(Mandatory = $true)][AllowNull()]$Value)
    return , (ConvertFrom-WtJson (ConvertTo-WtCanonicalJson $Value))
}

#endregion

#region Files and typed fields

function Read-WtJsonFile {
    # Strict read: UTF-8 without BOM, strict grammar.
    #  -Object     the top-level value must be an object
    #  -Canonical  the bytes must equal canonical JSON + LF exactly
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Object,
        [switch]$Canonical
    )
    $text = Read-WtText $Path
    try { $value = ConvertFrom-WtJson $text }
    catch { throw (New-WtFailure (Get-WtFailureCode $_) ('{0} :: {1}' -f $Path, (Get-WtFailureMessage $_))) }
    if ($Object -and $value -isnot [System.Collections.Specialized.OrderedDictionary]) { throw (New-WtFailure 'JSON_NOT_OBJECT' $Path) }
    if ($Canonical -and -not [string]::Equals(((ConvertTo-WtCanonicalJson $value) + "`n"), $text, [StringComparison]::Ordinal)) {
        throw (New-WtFailure 'JSON_NOT_CANONICAL' $Path)
    }
    return , $value
}

function Write-WtJsonFile {
    # Canonical JSON + LF, written atomically and durably.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowNull()]$Value)
    Write-WtBytes -Path $Path -Bytes (ConvertTo-WtUtf8 ((ConvertTo-WtCanonicalJson $Value) + "`n"))
}

function Test-WtField {
    [OutputType([bool])]
    param([AllowNull()]$Object, [Parameter(Mandatory = $true)][string]$Name)
    return ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name))
}

function Get-WtField {
    # Required, typed field access; fails closed with FIELD_MISSING or FIELD_TYPE.
    #   any | string | text (non-empty) | int | bool | object | array | hex64 | utc
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateSet('any', 'string', 'text', 'int', 'bool', 'object', 'array', 'hex64', 'utc')][string]$Type = 'any',
        [string]$Context = '$'
    )
    $where = '{0}.{1}' -f $Context, $Name
    if ($Object -isnot [System.Collections.IDictionary]) { throw (New-WtFailure 'FIELD_PARENT_NOT_OBJECT' $where) }
    if (-not $Object.Contains($Name)) { throw (New-WtFailure 'FIELD_MISSING' $where) }
    $value = $Object[$Name]
    $valid = switch ($Type) {
        'any' { $true }
        'string' { $value -is [string] }
        'text' { $value -is [string] -and $value.Length -gt 0 }
        'int' { $value -is [long] -or $value -is [int] }
        'bool' { $value -is [bool] }
        'object' { $value -is [System.Collections.IDictionary] }
        'array' { $value -is [System.Collections.IList] -and $value -isnot [System.Collections.IDictionary] }
        'hex64' { $value -is [string] -and (Test-WtHex64 $value) }
        'utc' { $value -is [string] -and $value -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' }
    }
    if (-not $valid) { throw (New-WtFailure 'FIELD_TYPE' ('{0} expected {1}' -f $where, $Type)) }
    return , $value
}

#endregion
