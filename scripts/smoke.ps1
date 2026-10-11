<#
.SYNOPSIS
  Compose smoke test on a disposable project ("halka-smoke"): empty init and up, HTTPS and cookie checks, SSO
  across the application containers, machine client, non-root and read-only containers, image and log secret
  scan, restart persistence, database outage and recovery, identity provider outage and recovery.

.DESCRIPTION
  Uses its own Compose project name, ports (9453-9456), database volume and private directory (.local-smoke). The
  developer stack ("halka", .local) is never touched. Everything the smoke run created (containers, volume,
  private directory, images) is removed at the end unless -Keep is given.
#>
[CmdletBinding()]
param(
    [int] $PortBase = 9453,
    [switch] $Keep
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = 'halka-smoke'
$localPath = Join-Path $root '.local-smoke'
$stack = Join-Path $PSScriptRoot 'local-stack.ps1'
$composeFile = Join-Path $root 'deploy/docker-compose.yml'
$logDirectory = Join-Path $root 'artifacts/verification/raw'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$results = [System.Collections.Generic.List[string]]::new()
$failed = $false

$env:HALKA_SMOKE_PROJECT = $project
$env:HALKA_SMOKE_LOCAL_DIR = $localPath
$env:HALKA_SMOKE_PORT_BASE = "$PortBase"
$env:HALKA_SMOKE_COMPOSE_FILE = $composeFile
$env:DOTNET_CLI_UI_LANGUAGE = 'en'

# Compose variables for the commands this script and the smoke tests run directly.
$env:HALKA_PROJECT = $project
$env:HALKA_LOCAL_DIR = $localPath
$env:HALKA_IAM_PORT = "$PortBase"
$env:HALKA_PANO_PORT = "$($PortBase + 1)"
$env:HALKA_RAPOR_PORT = "$($PortBase + 2)"
$env:HALKA_API_PORT = "$($PortBase + 3)"

function Invoke-Native([string] $File, [string[]] $Arguments, [string] $Log) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $File @Arguments 2>&1 | ForEach-Object { "$_" } | Set-Content -LiteralPath $Log -Encoding utf8 }
    finally { $ErrorActionPreference = $previous }
}

function Invoke-Phase([string] $Phase) {
    $log = Join-Path $logDirectory "smoke-phase-$Phase.log"
    Invoke-Native 'dotnet' @('run', '--project', (Join-Path $root 'tests/Halka.Smoke'), '-c', 'Release', '--no-build', '--', '--filter-trait', "Phase=$Phase") $log
    $exit = $LASTEXITCODE
    $summary = (Get-Content -LiteralPath $log | Where-Object { $_ -match '^\s*(total|failed|succeeded|skipped):' } | ForEach-Object { $_.Trim() }) -join ' '
    $script:results.Add("phase=$Phase exit=$exit $summary")
    if ($exit -ne 0) {
        $script:failed = $true
        Get-Content -LiteralPath $log | Where-Object { $_ -match '^failed |Assert|Expected|Actual|Exception' } | Select-Object -First 30 | ForEach-Object { Write-Output "    $_" }
    }
}

function Invoke-ComposeQuiet {
    Invoke-Native 'docker' (@('compose', '-f', $composeFile, '-p', $project) + $args) (Join-Path $logDirectory 'smoke-compose.log')
    if ($LASTEXITCODE -ne 0) { throw "docker compose $($args -join ' ') failed with exit code $LASTEXITCODE" }
}

try {
    Invoke-Native 'dotnet' @('build', (Join-Path $root 'tests/Halka.Smoke'), '-c', 'Release', '-v', 'q', '-nologo') (Join-Path $logDirectory 'smoke-build.log')
    if ($LASTEXITCODE -ne 0) { throw 'smoke test project did not build' }

    # A previous aborted run may have left the disposable project behind; it is ours to remove.
    if (Test-Path -LiteralPath (Join-Path $localPath 'manifest.json')) {
        & $stack reset -Project $project -PortBase $PortBase -ConfirmProject $project | Out-Null
    }

    & $stack up -Project $project -PortBase $PortBase > (Join-Path $logDirectory 'smoke-up.log')
    $results.Add('empty init + up: ok')
    Invoke-ComposeQuiet --profile machine build machine-demo
    Invoke-Phase 'up'

    & $stack down -Project $project -PortBase $PortBase > (Join-Path $logDirectory 'smoke-down.log')
    & $stack up -Project $project -PortBase $PortBase -NoBuild > (Join-Path $logDirectory 'smoke-up-again.log')
    $results.Add('down + up (volume and private directory kept): ok')
    Invoke-Phase 'restarted'

    Invoke-ComposeQuiet stop postgres
    Invoke-Phase 'db-down'
    Invoke-ComposeQuiet start postgres
    Invoke-Phase 'db-recovered'

    Invoke-ComposeQuiet stop iam
    Invoke-Phase 'op-down'
    Invoke-ComposeQuiet start iam
    Invoke-Phase 'op-recovered'
}
catch {
    $failed = $true
    $results.Add("smoke aborted: $($_.Exception.Message)")
}
finally {
    if (-not $Keep) {
        try {
            & $stack reset -Project $project -PortBase $PortBase -ConfirmProject $project | Out-Null

            # Images of the disposable project only: the reference filter cannot match the developer stack's images.
            $images = @(& docker image ls --filter "reference=$project-*" --format '{{.Repository}}:{{.Tag}}' | Where-Object { $_ -like "$project-*" })
            if ($images.Count -gt 0) { Invoke-Native 'docker' (@('image', 'rm') + $images) (Join-Path $logDirectory 'smoke-image-rm.log') }
            $results.Add("cleanup: disposable project, volume, .local-smoke and $($images.Count) images removed")
        }
        catch {
            $failed = $true
            $results.Add("cleanup failed: $($_.Exception.Message)")
        }
    }
}

$results | ForEach-Object { Write-Output $_ }
if ($failed) { Write-Output 'smoke exit=1'; exit 1 }
Write-Output 'smoke exit=0'
exit 0
