<#
.SYNOPSIS
  Prints a SHA-256 fingerprint of the source state: every tracked or untracked-but-not-ignored file except
  documentation (docs/) and verification output (artifacts/). Test results are only valid for the fingerprint they
  were produced with.
#>
[CmdletBinding()]
param([switch] $List)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$files = & git -C $root ls-files --cached --others --exclude-standard |
    Where-Object { $_ -and $_ -notmatch '^(docs|artifacts)/' } |
    Sort-Object -Unique

$sha = [System.Security.Cryptography.SHA256]::Create()
$builder = [System.Text.StringBuilder]::new()
foreach ($file in $files) {
    $path = Join-Path $root $file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $hash = [System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes($path))).Replace('-', '').ToLowerInvariant()
    [void] $builder.Append($file).Append("`t").Append($hash).Append("`n")
    if ($List) { Write-Output "$hash  $file" }
}

$total = [System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($builder.ToString()))).Replace('-', '').ToLowerInvariant()
Write-Output ("source-fingerprint sha256:{0} files={1}" -f $total, $files.Count)
