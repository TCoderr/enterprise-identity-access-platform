<#
.SYNOPSIS
  Repository hygiene scan: private key and secret material, authorship metadata, dependency advisories, lock files
  and container exposure. Prints one line per check; findings name the file and the rule, never the matched value.

.DESCRIPTION
  The scan first runs against a planted sample (positive control) and fails if it does not detect it, so an empty
  result means "nothing found" and not "the scanner looked at nothing".

.EXAMPLE
  ./scripts/scan.ps1
  ./scripts/scan.ps1 -Offline     # skips the advisory lookups that need the package feeds
#>
[CmdletBinding()]
param([switch] $Offline)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$env:DOTNET_CLI_UI_LANGUAGE = 'en'
$failed = $false
$self = $MyInvocation.MyCommand.Path

function Report([bool] $Ok, [string] $Name, [string[]] $Details = @()) {
    if ($Ok) { Write-Output "[ok]   $Name" }
    else {
        $script:failed = $true
        Write-Output "[FAIL] $Name"
        $Details | Select-Object -First 20 | ForEach-Object { Write-Output "         $_" }
    }
}

function Invoke-Native([string] $File, [string[]] $Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $File @Arguments 2>&1 | ForEach-Object { "$_" } }
    finally { $ErrorActionPreference = $previous }
}

# Build output, dependencies, private local material and raw test logs are not part of the source.
$excludedDirectories = '\\(bin|obj|node_modules|\.git|\.vs|TestResults|publish|\.local(-[a-z0-9]+)?)\\|\\artifacts\\(verification\\raw|tmp)\\'
$binaryExtensions = @('.png', '.jpg', '.ico', '.gif', '.woff', '.woff2', '.dll', '.exe', '.pdb', '.zip')

# Exclusions are judged on the path below the scanned directory, so the scan root itself may live anywhere.
function Get-SourceFiles([string] $Path) {
    $base = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    Get-ChildItem -LiteralPath $Path -Recurse -File -Force |
        Where-Object { ($_.FullName.Substring($base.Length) + '\') -notmatch $excludedDirectories -and $binaryExtensions -notcontains $_.Extension.ToLowerInvariant() }
}

# Patterns are matched culture-invariantly: with a Turkish system locale "I" and "i" are different letters, and
# an ordinary case-insensitive match would miss upper-case spellings.
$regexOptions = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
function Test-Pattern([string] $Text, [string] $Pattern) { [regex]::IsMatch($Text, $Pattern, $script:regexOptions) }

$authorshipPattern = '\b(claude|anthropic|openai|codex|chatgpt|copilot)\b|co-authored-by|generated (with|by) '
$secretRules = [ordered]@{
    'pem-private-key'      = '-----BEGIN (RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----'
    # A literal password inside a connection string: "Host=...;...;Password=value".
    'connection-password'  = '\b(Host|Server|Data Source)\s*=[^;"''\r\n]+;[^"''\r\n]*\bPassword\s*=\s*(?!design\b)[^;{}$\s"'']{4,}'
    'bearer-or-basic-value' = '\bAuthorization:\s*(Bearer|Basic)\s+[A-Za-z0-9+/_\-\.=]{20,}'
    'cloud-access-key'     = '\bAKIA[0-9A-Z]{16}\b'
}

# Narrow, reasoned suppressions (rule and exact file). Everything else that matches is a finding.
$suppressions = @(
    # The image scanner's own detection rule and its positive-control canary contain the PEM header text.
    'pem-private-key | tests\Halka.Smoke\ImageScanner.cs'
)

# Returns findings as "rule | relative path". Values are never part of the output.
function Find-Problems([string] $Path, [string[]] $ExactValues = @()) {
    $findings = [System.Collections.Generic.List[string]]::new()
    $base = [System.IO.Path]::GetFullPath($Path).TrimEnd('\') + '\'
    foreach ($file in Get-SourceFiles $Path) {
        $relative = $file.FullName.Substring($base.Length)
        if ($file.Extension -match '^\.(pfx|p12|key|pem|jks)$') { $findings.Add("key-file-name | $relative") }
        if ($file.FullName -eq $self) { continue }
        $text = [System.IO.File]::ReadAllText($file.FullName)
        if (Test-Pattern $text $authorshipPattern) { $findings.Add("authorship-term | $relative") }

        # Tests build throw-away connection strings and key material for disposable servers at run time.
        $isTest = $relative -match '^tests\\'
        foreach ($rule in $secretRules.GetEnumerator()) {
            if ($isTest -and $rule.Key -eq 'connection-password') { continue }
            if (Test-Pattern $text $rule.Value) { $findings.Add("$($rule.Key) | $relative") }
        }
        foreach ($value in $ExactValues) {
            if ($value.Length -ge 12 -and $text.Contains($value)) { $findings.Add("local-secret-value | $relative") }
        }
    }
    return ,$findings
}

# --- Positive control -------------------------------------------------------------------------------------------
$sample = Join-Path $root "artifacts/tmp/scan-control-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $sample | Out-Null
try {
    $planted = 'planted-' + [Guid]::NewGuid().ToString('N')
    Set-Content -LiteralPath (Join-Path $sample 'notes.md') -Value ('Co-' + 'Authored-By: someone') -Encoding utf8
    Set-Content -LiteralPath (Join-Path $sample 'key.txt') -Value ('-----BEGIN ' + 'PRIVATE KEY-----') -Encoding utf8
    Set-Content -LiteralPath (Join-Path $sample 'settings.json') -Value ('"Host=db;Pass' + 'word=hunter2hunter2"') -Encoding utf8
    Set-Content -LiteralPath (Join-Path $sample 'copy.txt') -Value "value: $planted" -Encoding utf8
    Set-Content -LiteralPath (Join-Path $sample 'server.pfx') -Value 'x' -Encoding utf8
    Set-Content -LiteralPath (Join-Path $sample 'upper.md') -Value ('made with OPEN' + 'AI tools') -Encoding utf8
    Set-Content -LiteralPath (Join-Path $sample 'clean.txt') -Value 'nothing to see here' -Encoding utf8
    $control = Find-Problems $sample @($planted)
    $expected = @('authorship-term | notes.md', 'authorship-term | upper.md', 'pem-private-key | key.txt', 'connection-password | settings.json', 'local-secret-value | copy.txt', 'key-file-name | server.pfx')
    $missing = @($expected | Where-Object { $control -notcontains $_ })
    $falsePositive = @($control | Where-Object { $_ -like '* | clean.txt' })
    Report ($missing.Count -eq 0 -and $falsePositive.Count -eq 0) 'positive control: planted findings are detected, clean file is not' ($missing + $falsePositive)
}
finally {
    Remove-Item -LiteralPath $sample -Recurse -Force
}

# --- Source scan ------------------------------------------------------------------------------------------------
# When a local stack was initialised, its real secret values are searched for as well (values stay in memory).
$exact = [System.Collections.Generic.List[string]]::new()
foreach ($local in Get-ChildItem -LiteralPath $root -Directory -Force -Filter '.local*') {
    $secrets = Join-Path $local.FullName 'secrets'
    if (Test-Path -LiteralPath $secrets) {
        Get-ChildItem -LiteralPath $secrets -File | ForEach-Object { $exact.Add(([System.IO.File]::ReadAllText($_.FullName)).Trim()) }
    }
    $seed = Join-Path $local.FullName 'seed/credentials.json'
    if (Test-Path -LiteralPath $seed) {
        (Get-Content -LiteralPath $seed -Raw | ConvertFrom-Json).users | ForEach-Object { $exact.Add($_.password) }
    }
}
$all = Find-Problems $root $exact.ToArray()
$findings = @($all | Where-Object { $suppressions -notcontains $_ })
$unused = @($suppressions | Where-Object { $all -notcontains $_ })
Report ($findings.Count -eq 0) "source scan: no key material, secret values or authorship terms ($($exact.Count) local secret values checked, $($all.Count - $findings.Count) suppressed)" $findings
Report ($unused.Count -eq 0) 'suppressions: every suppression still matches something' $unused

# --- Authorship metadata ----------------------------------------------------------------------------------------
$props = Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Raw
Report ($props -match '<Authors>TCoderr</Authors>') 'package metadata: Authors is TCoderr'
$readme = Join-Path $root 'README.md'
Report ((Test-Path -LiteralPath $readme) -and ((Get-Content -LiteralPath $readme -Raw) -match 'TCoderr')) 'README names TCoderr as author'
Report (Test-Path -LiteralPath (Join-Path $root 'THIRD-PARTY-NOTICES.md')) 'third-party notices are present'

# --- Lock files and git ignore ----------------------------------------------------------------------------------
$projects = Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.csproj' | Where-Object { ($_.FullName + '\') -notmatch $excludedDirectories }
$unlocked = @($projects | Where-Object { -not (Test-Path -LiteralPath (Join-Path $_.DirectoryName 'packages.lock.json')) } | ForEach-Object { $_.Name })
Report ($unlocked.Count -eq 0) "lock files: every project ($($projects.Count)) has packages.lock.json" $unlocked
Report (Test-Path -LiteralPath (Join-Path $root 'src/Halka.Iam/ui-tooling/package-lock.json')) 'lock files: UI tooling has package-lock.json'
$ignore = Get-Content -LiteralPath (Join-Path $root '.gitignore')
Report (($ignore -contains '.local/') -and ($ignore -contains '.local-*/') -and ($ignore -contains '*.key') -and ($ignore -contains '*.pfx')) 'git ignore covers private local material and key files'

# --- Containers -------------------------------------------------------------------------------------------------
$compose = Get-Content -LiteralPath (Join-Path $root 'deploy/docker-compose.yml')
$ports = @($compose | Where-Object { $_ -cmatch '^\s*-\s*"[^"]*\$\{HALKA_[A-Z]+_PORT[^"]*"\s*$' })
$exposed = @($ports | Where-Object { $_ -cnotmatch '^\s*-\s*"127\.0\.0\.1:' })
Report ($ports.Count -ge 4 -and $exposed.Count -eq 0) "compose: all $($ports.Count) published ports are bound to 127.0.0.1" $exposed
Report (@($compose | Where-Object { $_ -cmatch 'privileged:\s*true' }).Count -eq 0) 'compose: no privileged container'
$dockerfile = Get-Content -LiteralPath (Join-Path $root 'deploy/Dockerfile') -Raw
Report ($dockerfile -match '(?m)^USER\s+(?!root\b|0\b)\S+') 'Dockerfile: runtime image runs as a non-root user'

# --- Dependency advisories --------------------------------------------------------------------------------------
if ($Offline) {
    Write-Output '[skip] dependency advisories (-Offline)'
}
else {
    $nuget = Invoke-Native 'dotnet' @('list', (Join-Path $root 'Halka.slnx'), 'package', '--vulnerable', '--include-transitive')
    $nugetExit = $LASTEXITCODE
    $vulnerable = @($nuget | Where-Object { $_ -match 'has the following vulnerable packages|^\s*>\s' })
    Report ($nugetExit -eq 0 -and $vulnerable.Count -eq 0 -and ($nuget -match 'no vulnerable packages').Count -gt 0) 'NuGet: no package with a known vulnerability (direct and transitive)' $vulnerable

    Push-Location (Join-Path $root 'src/Halka.Iam/ui-tooling')
    try {
        $npm = Invoke-Native 'npm' @('audit', '--audit-level=low')
        $npmExit = $LASTEXITCODE
    }
    finally { Pop-Location }
    Report ($npmExit -eq 0) 'npm (UI tooling, development only): no known vulnerability' @($npm | Select-Object -Last 6)
}

if ($failed) { Write-Output 'scan exit=1'; exit 1 }
Write-Output 'scan exit=0'
exit 0
