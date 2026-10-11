<#
.SYNOPSIS
  Builds and runs one test project, writes the full log under artifacts/verification/raw (ignored by git) and prints
  a compact summary: counts, failed test names and the first lines of each failure.
.EXAMPLE
  ./scripts/test.ps1 -Project Integration
  ./scripts/test.ps1 -Project Integration -Filter '--filter-class' ,'*LoginAndSessionTests'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Unit', 'Integration', 'E2E')] [string] $Project,
    [string[]] $Filter = @(),
    [string] $Configuration = 'Debug',
    [switch] $NoBuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$env:DOTNET_CLI_UI_LANGUAGE = 'en'
$env:DOTNET_NOLOGO = '1'
$projectPath = Join-Path $root "tests/Halka.$($Project -replace '^Unit$','UnitTests' -replace '^Integration$','IntegrationTests')"
$logDirectory = Join-Path $root 'artifacts/verification/raw'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$log = Join-Path $logDirectory "test-$($Project.ToLowerInvariant()).log"

if (-not $NoBuild) {
    $build = & dotnet build $projectPath -c $Configuration --no-restore -v q -nologo 2>&1
    if ($LASTEXITCODE -ne 0) {
        $build | Where-Object { $_ -match 'error' } | Select-Object -Unique -First 40 | ForEach-Object { ($_ -replace [regex]::Escape($root + '\'), '') }
        Write-Output "build exit=$LASTEXITCODE"
        exit $LASTEXITCODE
    }
}

$arguments = @('test', '--project', $projectPath, '-c', $Configuration, '--no-build')
if ($Filter.Count -gt 0) { $arguments += '--'; $arguments += $Filter }
$started = Get-Date
$ErrorActionPreference = 'Continue'
& dotnet @arguments 2>&1 | ForEach-Object { "$_" } | Set-Content -LiteralPath $log -Encoding utf8
$exit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
$lines = Get-Content -LiteralPath $log

$failed = $lines | Where-Object { $_ -match '^failed ' }
foreach ($name in $failed) {
    Write-Output $name
    $index = [array]::IndexOf($lines, $name)
    $lines[($index + 1)..([Math]::Min($index + 9, $lines.Count - 1))] |
        Where-Object { $_ -notmatch '^\s+from ' } |
        ForEach-Object { '    ' + ($_ -replace [regex]::Escape($root + '\'), '').Trim() }
}

$lines | Where-Object { $_ -match '^\s*(total|failed|succeeded|skipped|duration):' -or $_ -match '^Test run summary' } | ForEach-Object { $_.Trim() }
Write-Output ("test exit={0} elapsed={1:n0}s log={2}" -f $exit, ((Get-Date) - $started).TotalSeconds, ($log -replace [regex]::Escape($root + '\'), ''))
exit $exit
