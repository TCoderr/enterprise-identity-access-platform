<#
.SYNOPSIS
  Manages the local Halka ID stack (Docker Compose).

.DESCRIPTION
  init    Creates private local material (.local/): CA and TLS certificates, passwords, client secrets, Data
          Protection wrapping certificates, PostgreSQL bootstrap script, seed credentials. Idempotent.
  up      Runs init if needed, builds images, starts the stack and waits until it is healthy.
  down    Stops and removes containers. Volumes and .local/ are kept, so data, keys and sessions survive.
  status  Shows container state and URLs.
  logs    Shows recent logs (optionally for one service).
  machine Runs the machine-to-machine demo once in its own container (client credentials, then an API call).
          The stack must be up.
  reset   DESTRUCTIVE: removes containers, the database volume and the private local directory of this project.
          Requires -ConfirmProject <project name> and only works on a directory created by init.

.EXAMPLE
  ./scripts/local-stack.ps1 up
  ./scripts/local-stack.ps1 logs -Service iam
  ./scripts/local-stack.ps1 machine
  ./scripts/local-stack.ps1 reset -ConfirmProject halka
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('init', 'up', 'down', 'status', 'logs', 'machine', 'reset')]
    [string] $Command,
    [ValidatePattern('^halka(-[a-z0-9]+)?$')]
    [string] $Project = 'halka',
    [ValidateRange(1024, 65000)]
    [int] $PortBase = 9443,
    [string] $Service,
    [string] $ConfirmProject,
    [switch] $NoBuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$localName = if ($Project -eq 'halka') { '.local' } else { '.local-' + ($Project -replace '^halka-', '') }
$localPath = Join-Path $root $localName
$composeFile = Join-Path $root 'deploy/docker-compose.yml'

$env:HALKA_PROJECT = $Project
$env:HALKA_LOCAL_DIR = $localPath
$env:HALKA_IAM_PORT = "$PortBase"
$env:HALKA_PANO_PORT = "$($PortBase + 1)"
$env:HALKA_RAPOR_PORT = "$($PortBase + 2)"
$env:HALKA_API_PORT = "$($PortBase + 3)"
$env:DOTNET_CLI_UI_LANGUAGE = 'en'

# Native tools write progress to stderr. Windows PowerShell 5.1 turns redirected stderr into errors, so both
# streams are merged into plain text here and only the exit code decides success.
function Invoke-Native([string] $File, [string[]] $Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $File @Arguments 2>&1 | ForEach-Object { "$_" } }
    finally { $ErrorActionPreference = $previous }
}

function Invoke-Compose {
    Invoke-Native 'docker' (@('compose', '-f', $composeFile, '-p', $Project) + $args)
    if ($LASTEXITCODE -ne 0) { throw "docker compose $($args -join ' ') failed with exit code $LASTEXITCODE" }
}

function Invoke-Init {
    Invoke-Native 'dotnet' @('run', '--project', (Join-Path $root 'tools/Halka.LocalInit'), '-c', 'Release', '--', '--target', $localPath)
    if ($LASTEXITCODE -ne 0) { throw "local init failed with exit code $LASTEXITCODE" }
}

function Show-Urls {
    Write-Output ''
    Write-Output "Halka ID   https://id.halka.localhost:$($env:HALKA_IAM_PORT)"
    Write-Output "Pano       https://pano.localhost:$($env:HALKA_PANO_PORT)"
    Write-Output "Rapor      https://rapor.localhost:$($env:HALKA_RAPOR_PORT)"
    Write-Output "API        https://workspace-api.localhost:$($env:HALKA_API_PORT)"
    Write-Output "Private    $localPath  (seed/credentials.json, mail-sink/, tls/ca.crt)"
}

switch ($Command) {
    'init' {
        Invoke-Init
    }
    'up' {
        if (-not (Test-Path -LiteralPath (Join-Path $localPath 'manifest.json'))) { Invoke-Init }
        if ($NoBuild) { Invoke-Compose up -d --wait --wait-timeout 180 } else { Invoke-Compose up -d --build --wait --wait-timeout 180 }
        Show-Urls
    }
    'down' {
        # Deliberately no "-v": the database volume and the private directory are preserved.
        Invoke-Compose down --remove-orphans
    }
    'status' {
        Invoke-Compose ps --all
        Show-Urls
    }
    'logs' {
        if ($Service) { Invoke-Compose logs --no-color --tail 200 $Service } else { Invoke-Compose logs --no-color --tail 200 }
    }
    'machine' {
        Invoke-Compose --profile machine run --rm --no-deps machine-demo
    }
    'reset' {
        if ($ConfirmProject -cne $Project) {
            throw "reset is destructive. Re-run with -ConfirmProject $Project to delete the database volume and '$localName'."
        }

        # Target guard: only a directory inside this repository that init created for this layout is ever deleted.
        $resolvedRoot = [System.IO.Path]::GetFullPath($root).TrimEnd('\', '/')
        $resolvedLocal = [System.IO.Path]::GetFullPath($localPath).TrimEnd('\', '/')
        $insideRepository = $resolvedLocal.StartsWith($resolvedRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
        $nameIsExpected = (Split-Path -Leaf $resolvedLocal) -like '.local*'
        if (-not $insideRepository -or -not $nameIsExpected) { throw "Refusing to reset: '$resolvedLocal' is not a private directory of this repository." }

        Invoke-Compose down --volumes --remove-orphans
        if (Test-Path -LiteralPath $resolvedLocal) {
            if (-not (Test-Path -LiteralPath (Join-Path $resolvedLocal 'manifest.json'))) {
                throw "Refusing to delete '$resolvedLocal': it has no manifest.json written by init."
            }
            Remove-Item -LiteralPath $resolvedLocal -Recurse -Force
        }
        Write-Output "reset complete for project '$Project'."
    }
}
