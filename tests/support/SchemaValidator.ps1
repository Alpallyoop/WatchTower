# A strict validator for the JSON Schema (draft 2020-12) subset used by schemas/*.json.
#
# Any keyword outside the supported set fails validation of the schema itself
# (SCHEMA_KEYWORD_UNSUPPORTED), so a schema can never carry a constraint that nothing
# checks. Values are the structures produced by ConvertFrom-WtJson; the module's private JSON
# helpers (Read-WtJsonFile, ConvertTo-WtCanonicalJson) must be in scope, as they are in the
# test suites and inside the module scope used by Invoke-WatchTowerTests.ps1.

$script:SchemaKeywords = @(
    '$schema', '$id', 'title', 'description', '$comment', 'examples', 'schema', '$defs', '$ref',
    'type', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const',
    'pattern', 'minLength', 'maxLength', 'minimum', 'maximum', 'minItems', 'maxItems',
    'allOf', 'if', 'then', 'else', 'not')

function Get-JsonTypeName {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return 'boolean' }
    if ($Value -is [long] -or $Value -is [int]) { return 'integer' }
    if ($Value -is [string]) { return 'string' }
    if ($Value -is [System.Collections.IDictionary]) { return 'object' }
    if ($Value -is [System.Collections.IList]) { return 'array' }
    return 'unsupported:' + $Value.GetType().Name
}

function Test-SchemaNode {
    param($Schema, [AllowNull()]$Value, $Root, [string]$Path, [System.Collections.Generic.List[string]]$Errors)
    if ($Schema -is [bool]) { if (-not $Schema) { $Errors.Add("${Path}: not allowed") }; return }
    if (-not ($Schema -is [System.Collections.IDictionary])) { throw ('SCHEMA_NOT_AN_OBJECT at ' + $Path) }
    foreach ($keyword in $Schema.PSBase.Keys) {
        if ($script:SchemaKeywords -cnotcontains $keyword) { throw ('SCHEMA_KEYWORD_UNSUPPORTED: {0} at {1}' -f $keyword, $Path) }
    }
    if ($Schema.Contains('$ref')) {
        $reference = [string]$Schema['$ref']
        if ($reference -cnotmatch '^#/\$defs/([A-Za-z0-9_]+)$' -or -not $Root['$defs'].Contains($Matches[1])) { throw ('SCHEMA_REF_UNRESOLVED: ' + $reference) }
        Test-SchemaNode $Root['$defs'][$Matches[1]] $Value $Root $Path $Errors
    }
    $type = Get-JsonTypeName $Value
    if ($Schema.Contains('type')) {
        $allowed = @($Schema['type'])
        if ($allowed -cnotcontains $type) { $Errors.Add(('{0}: type {1}, expected {2}' -f $Path, $type, ($allowed -join '|'))); return }
    }
    if ($Schema.Contains('const') -and (ConvertTo-WtCanonicalJson $Value) -cne (ConvertTo-WtCanonicalJson $Schema['const'])) { $Errors.Add(('{0}: must equal {1}' -f $Path, (ConvertTo-WtCanonicalJson $Schema['const']))) }
    if ($Schema.Contains('enum')) {
        $canonical = ConvertTo-WtCanonicalJson $Value
        if (@($Schema['enum'] | ForEach-Object { ConvertTo-WtCanonicalJson $_ }) -cnotcontains $canonical) { $Errors.Add(('{0}: {1} not in enum' -f $Path, $canonical)) }
    }
    if ($type -eq 'string') {
        if ($Schema.Contains('pattern') -and $Value -cnotmatch [string]$Schema['pattern']) { $Errors.Add(('{0}: "{1}" does not match {2}' -f $Path, $Value, $Schema['pattern'])) }
        if ($Schema.Contains('minLength') -and $Value.Length -lt [long]$Schema['minLength']) { $Errors.Add("${Path}: shorter than minLength") }
        if ($Schema.Contains('maxLength') -and $Value.Length -gt [long]$Schema['maxLength']) { $Errors.Add("${Path}: longer than maxLength") }
    }
    if ($type -eq 'integer') {
        if ($Schema.Contains('minimum') -and $Value -lt [long]$Schema['minimum']) { $Errors.Add("${Path}: below minimum") }
        if ($Schema.Contains('maximum') -and $Value -gt [long]$Schema['maximum']) { $Errors.Add("${Path}: above maximum") }
    }
    if ($type -eq 'array') {
        if ($Schema.Contains('minItems') -and $Value.Count -lt [long]$Schema['minItems']) { $Errors.Add("${Path}: fewer than minItems") }
        if ($Schema.Contains('maxItems') -and $Value.Count -gt [long]$Schema['maxItems']) { $Errors.Add("${Path}: more than maxItems") }
        if ($Schema.Contains('items')) { for ($i = 0; $i -lt $Value.Count; $i++) { Test-SchemaNode $Schema['items'] $Value[$i] $Root ('{0}[{1}]' -f $Path, $i) $Errors } }
    }
    if ($type -eq 'object') {
        if ($Schema.Contains('required')) { foreach ($name in $Schema['required']) { if (-not $Value.Contains($name)) { $Errors.Add(('{0}: missing required "{1}"' -f $Path, $name)) } } }
        $properties = $(if ($Schema.Contains('properties')) { $Schema['properties'] } else { $null })
        foreach ($name in $Value.PSBase.Keys) {
            if ($null -ne $properties -and $properties.Contains($name)) { Test-SchemaNode $properties[$name] $Value[$name] $Root ('{0}.{1}' -f $Path, $name) $Errors }
            elseif ($Schema.Contains('additionalProperties')) { Test-SchemaNode $Schema['additionalProperties'] $Value[$name] $Root ('{0}.{1}' -f $Path, $name) $Errors }
        }
    }
    if ($Schema.Contains('allOf')) { foreach ($sub in $Schema['allOf']) { Test-SchemaNode $sub $Value $Root $Path $Errors } }
    if ($Schema.Contains('if')) {
        $probe = New-Object System.Collections.Generic.List[string]
        Test-SchemaNode $Schema['if'] $Value $Root $Path $probe
        if ($probe.Count -eq 0) { if ($Schema.Contains('then')) { Test-SchemaNode $Schema['then'] $Value $Root $Path $Errors } }
        elseif ($Schema.Contains('else')) { Test-SchemaNode $Schema['else'] $Value $Root $Path $Errors }
    }
    if ($Schema.Contains('not')) {
        $probe = New-Object System.Collections.Generic.List[string]
        Test-SchemaNode $Schema['not'] $Value $Root $Path $probe
        if ($probe.Count -eq 0) { $Errors.Add("${Path}: matches a forbidden shape") }
    }
}

function Assert-SchemaSupported {
    # Walks every subschema position statically, so an unsupported keyword is found even in
    # branches that no test value happens to reach.
    param($Schema, [string]$Path = '$', $Root = $null)
    if ($null -eq $Root) { $Root = $Schema }
    if ($Schema -is [bool]) { return }
    if (-not ($Schema -is [System.Collections.IDictionary])) { throw ('SCHEMA_NOT_AN_OBJECT at ' + $Path) }
    foreach ($keyword in $Schema.PSBase.Keys) {
        if ($script:SchemaKeywords -cnotcontains $keyword) { throw ('SCHEMA_KEYWORD_UNSUPPORTED: {0} at {1}' -f $keyword, $Path) }
    }
    foreach ($map in @('properties', '$defs')) {
        if ($Schema.Contains($map)) { foreach ($name in $Schema[$map].PSBase.Keys) { Assert-SchemaSupported $Schema[$map][$name] ('{0}.{1}.{2}' -f $Path, $map, $name) $Root } }
    }
    foreach ($single in @('items', 'additionalProperties', 'if', 'then', 'else', 'not')) {
        if ($Schema.Contains($single)) { Assert-SchemaSupported $Schema[$single] ('{0}.{1}' -f $Path, $single) $Root }
    }
    if ($Schema.Contains('allOf')) { $i = 0; foreach ($sub in $Schema['allOf']) { Assert-SchemaSupported $sub ('{0}.allOf[{1}]' -f $Path, $i) $Root; $i++ } }
    if ($Schema.Contains('pattern')) { [void](New-Object System.Text.RegularExpressions.Regex ([string]$Schema['pattern'])) }
    if ($Schema.Contains('$ref')) {
        $reference = [string]$Schema['$ref']
        if ($reference -cnotmatch '^#/\$defs/([A-Za-z0-9_]+)$' -or -not $Root.Contains('$defs') -or -not $Root['$defs'].Contains($Matches[1])) { throw ('SCHEMA_REF_UNRESOLVED: {0} at {1}' -f $reference, $Path) }
    }
}

function Get-SchemaErrors {
    # Validation errors of $Value against the schema document at $SchemaPath (empty = valid).
    param([Parameter(Mandatory = $true)][string]$SchemaPath, [AllowNull()]$Value)
    # Fail closed whatever the caller's preference: an error inside validation must never
    # read as "no validation errors".
    $ErrorActionPreference = 'Stop'
    $schema = Read-WtJsonFile -Path $SchemaPath -Object
    $errors = New-Object System.Collections.Generic.List[string]
    Test-SchemaNode $schema $Value $schema '$' $errors
    return , $errors.ToArray()
}

function Assert-MatchesSchema {
    param([Parameter(Mandatory = $true)][string]$SchemaPath, [AllowNull()]$Value, [string]$What = 'value')
    $errors = Get-SchemaErrors -SchemaPath $SchemaPath -Value $Value
    if ($errors.Length -gt 0) { throw ('{0} violates {1}: {2}' -f $What, [System.IO.Path]::GetFileName($SchemaPath), ($errors -join '; ')) }
}
