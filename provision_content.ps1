# Provisions ImHex content (magic database, Pattern Language std-library, patterns,
# encodings, constants, nodes) so the headless MCP server can use libmagic, run_pattern_file
# includes, and suggest_patterns.
#
# Content comes from the official WerWolv/ImHex-Patterns repository.
#
# Usage:
#   .\provision_content.ps1                      # install to %LOCALAPPDATA%\imhex
#   .\provision_content.ps1 -TargetDir C:\imhex-content   # custom dir (set IMHEX_CONTENT_DIR to it)
#
# After provisioning, the headless server compiles the magic db automatically on startup.

param(
    [string]$TargetDir = (Join-Path $env:LOCALAPPDATA "imhex"),
    [string]$CacheDir  = (Join-Path (Split-Path $PSScriptRoot -Parent) ".imhex-content")
)

$ErrorActionPreference = "Stop"
$RepoUrl = "https://github.com/WerWolv/ImHex-Patterns.git"
$ContentDirs = @("magic", "includes", "patterns", "encodings", "constants", "nodes")

# 1. Fetch or update the content cache (shallow)
if (Test-Path (Join-Path $CacheDir ".git")) {
    Write-Host "Updating content cache at $CacheDir ..."
    git -C $CacheDir pull --depth 1 --ff-only
} else {
    Write-Host "Cloning ImHex-Patterns to $CacheDir ..."
    git clone --depth 1 $RepoUrl $CacheDir
}

# 2. Copy each content directory into the target data folder
New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
foreach ($dir in $ContentDirs) {
    $src = Join-Path $CacheDir $dir
    $dst = Join-Path $TargetDir $dir
    if (Test-Path $src) {
        New-Item -ItemType Directory -Force -Path $dst | Out-Null
        Write-Host "  Copying $dir ..."
        Copy-Item -Path (Join-Path $src "*") -Destination $dst -Recurse -Force
    } else {
        Write-Warning "  Source directory missing, skipping: $src"
    }
}

Write-Host ""
Write-Host "Content provisioned to: $TargetDir"
Write-Host "  magic source dirs: $((Get-ChildItem (Join-Path $TargetDir 'magic') -ErrorAction SilentlyContinue).Count)"
Write-Host "  includes:          $((Get-ChildItem (Join-Path $TargetDir 'includes') -Recurse -File -ErrorAction SilentlyContinue).Count) files"
Write-Host "  patterns:          $((Get-ChildItem (Join-Path $TargetDir 'patterns') -Filter *.hexpat -ErrorAction SilentlyContinue).Count) .hexpat"
Write-Host ""
Write-Host "The headless MCP server compiles the magic database on startup."
Write-Host "If you installed to a custom dir, set:  `$env:IMHEX_CONTENT_DIR = '$TargetDir'"
