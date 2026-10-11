<#
.SYNOPSIS
  Runs every local verification gate on one source state and prints a summary table.

.DESCRIPTION
  Order: source fingerprint, locked restore, Release build (warnings are errors), unit, integration and browser
  tests, UI tooling (type check, lint, script tests), publish check, repository scan, Compose smoke test, source
  fingerprint again. The run fails when any gate fails or when the fingerprint changed while it was running.
  Raw logs go to artifacts/verification/raw (ignored by git). Nothing is pushed and no remote CI is involved.

.EXAMPLE
  ./scripts/verify.ps1
  ./scripts/verify.ps1 -SkipSmoke     # without Docker Compose (the summary shows the gate as skipped)
#>
[CmdletBinding()]
param(
    [switch] $SkipSmoke,
    [switch] $Offline
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$env:DOTNET_CLI_UI_LANGUAGE = 'en'
$env:DOTNET_NOLOGO = '1'
$logDirectory = Join-Path $root 'artifacts/verification/raw'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$rows = [System.Collections.Generic.List[object]]::new()
$failed = $false

function Invoke-Native([string] $File, [string[]] $Arguments, [string] $WorkingDirectory = $root) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Push-Location $WorkingDirectory
    try { & $File @Arguments 2>&1 | ForEach-Object { "$_" } }
    finally { Pop-Location; $ErrorActionPreference = $previous }
}

# Log file name of a gate. Case-sensitive on purpose: a case-insensitive match follows the current culture, and
# under tr-TR "I" is then no longer part of [a-zA-Z] ("tests: Integration" became "tests-ntegration").
function Get-GateLogName([string] $Name) {
    'verify-{0}.log' -f ($Name -creplace '[^a-zA-Z0-9]+', '-').ToLowerInvariant().Trim('-')
}

# Runs one gate; the script block returns its output lines and leaves the exit code in $LASTEXITCODE.
function Invoke-Gate([string] $Name, [scriptblock] $Action, [scriptblock] $Summarize = { param($lines) '' }) {
    $started = Get-Date
    $global:LASTEXITCODE = 0
    $lines = @(& $Action)
    $exit = $LASTEXITCODE
    $log = Join-Path $logDirectory (Get-GateLogName $Name)
    $lines | Set-Content -LiteralPath $log -Encoding utf8
    if ($exit -ne 0) {
        $script:failed = $true
        Write-Output "--- $Name failed (exit $exit) ---"
        $lines | Where-Object { $_ -match 'error|failed |FAIL|Assert|Expected|Actual|aborted' } | Select-Object -First 25 |
            ForEach-Object { '    ' + ($_ -replace [regex]::Escape($root + '\'), '') }
    }
    $script:rows.Add([pscustomobject]@{
        Gate    = $Name
        Exit    = $exit
        Result  = (& $Summarize $lines)
        Seconds = [int]((Get-Date) - $started).TotalSeconds
    })
}

function Get-TestCounts($lines) {
    $pick = { param($label) (($lines | Where-Object { $_ -match "^\s*${label}:\s*(\d+)" } | Select-Object -Last 1) -replace '\D', '') }
    "total=$(& $pick 'total') passed=$(& $pick 'succeeded') failed=$(& $pick 'failed') skipped=$(& $pick 'skipped')"
}

$fingerprintScript = Join-Path $PSScriptRoot 'source-fingerprint.ps1'
$before = (& $fingerprintScript) -join ''
Write-Output "start  $before"

Invoke-Gate 'restore (locked)' { Invoke-Native 'dotnet' @('restore', 'Halka.slnx', '--locked-mode') }
Invoke-Gate 'build (Release)' { Invoke-Native 'dotnet' @('build', 'Halka.slnx', '-c', 'Release', '--no-restore', '-v', 'q') } {
    param($lines) (($lines | Where-Object { $_ -match '^\s*\d+ (Warning|Error)\(s\)' }) -join ' ').Trim() -replace '\s+', ' '
}

foreach ($project in 'Unit', 'Integration', 'E2E') {
    Invoke-Gate "tests: $project" { & (Join-Path $PSScriptRoot 'test.ps1') -Project $project -Configuration Release -NoBuild }.GetNewClosure() { param($lines) Get-TestCounts $lines }
}

Invoke-Gate 'UI tooling (typecheck, lint, script tests)' { Invoke-Native 'npm' @('run', 'check') (Join-Path $root 'src/Halka.Iam/ui-tooling') } {
    param($lines) (($lines | Where-Object { $_ -match '^# (tests|pass|fail) ' }) -join ' ') -replace '# ', ''
}

# Production publish of the applications; also proves that a published client carries the EF Core it was built for.
Invoke-Gate 'publish (Release)' {
    $output = Join-Path $root 'artifacts/tmp/publish'
    if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force }
    foreach ($project in 'Halka.Iam', 'Halka.Pano', 'Halka.Rapor', 'Halka.WorkspaceApi', 'Halka.MachineDemo', 'Halka.Migrator') {
        Invoke-Native 'dotnet' @('publish', "src/$project/$project.csproj", '-c', 'Release', '--no-restore', '-v', 'q', '-o', (Join-Path $output $project), '-p:UseAppHost=false')
        if ($LASTEXITCODE -ne 0) { return }
    }
    $expected = [regex]::Match((Get-Content -LiteralPath (Join-Path $root 'Directory.Packages.props') -Raw), 'Microsoft\.EntityFrameworkCore\.Relational" Version="([^"]+)"').Groups[1].Value
    foreach ($project in 'Halka.Iam', 'Halka.Pano', 'Halka.Rapor', 'Halka.Migrator') {
        $deps = Get-Content -LiteralPath (Join-Path $output "$project/$project.deps.json") -Raw
        if ($deps -notmatch [regex]::Escape("`"Microsoft.EntityFrameworkCore/$expected`"")) {
            "error: $project was published with another Microsoft.EntityFrameworkCore than $expected"
            $global:LASTEXITCODE = 1
            return
        }
    }
    "published 6 applications; Microsoft.EntityFrameworkCore $expected in every data-access application"
    Remove-Item -LiteralPath $output -Recurse -Force
    $global:LASTEXITCODE = 0
} { param($lines) ($lines | Select-Object -Last 1) }

$scanArguments = @{}
if ($Offline) { $scanArguments['Offline'] = $true }
Invoke-Gate 'scan (secrets, authorship, dependencies)' { & (Join-Path $PSScriptRoot 'scan.ps1') @scanArguments } {
    param($lines) "ok=$(@($lines | Where-Object { $_ -like '`[ok`]*' }).Count) fail=$(@($lines | Where-Object { $_ -like '`[FAIL`]*' }).Count) skip=$(@($lines | Where-Object { $_ -like '`[skip`]*' }).Count)"
}

if ($SkipSmoke) {
    $rows.Add([pscustomobject]@{ Gate = 'smoke (Compose)'; Exit = 'skipped'; Result = 'not run (-SkipSmoke)'; Seconds = 0 })
}
else {
    Invoke-Gate 'smoke (Compose)' { & (Join-Path $PSScriptRoot 'smoke.ps1') } {
        param($lines) (($lines | Where-Object { $_ -match '^phase=' } | ForEach-Object { ($_ -replace 'phase=(\S+) exit=(\d+).*succeeded: (\d+).*', '$1:$3/exit$2') }) -join ' ')
    }
}

$rows.Add([pscustomobject]@{ Gate = 'remote CI'; Exit = 'not run'; Result = 'no push was authorised; a local run is not a remote CI result'; Seconds = 0 })

$after = (& $fingerprintScript) -join ''
Write-Output ''
$rows | Format-Table -AutoSize -Wrap | Out-String -Width 220 | ForEach-Object { $_.TrimEnd() }
Write-Output "end    $after"
if ($before -ne $after) {
    $failed = $true
    Write-Output 'The source changed during the run; the results above do not describe one source state.'
}

if ($failed) { Write-Output 'verify exit=1'; exit 1 }
Write-Output 'verify exit=0'
exit 0
