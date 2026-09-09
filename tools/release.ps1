<#
.SYNOPSIS
Package a release archive and (optionally) publish it to GitHub.

.DESCRIPTION
Builds a source zip from the tracked files only, so nothing ignored or local
leaks into the archive. Optionally creates the tag, pushes it, and creates a
GitHub release with the zip attached.

Requires `git`; publishing additionally requires `gh` (authenticated).
If GitHub is unreachable directly, set HTTPS_PROXY first.

.PARAMETER Version
Release version, with or without a leading "v" (e.g. 0.1.1 or v0.1.1).

.PARAMETER Publish
When set, create the tag, push it, and create the GitHub release with the zip.

.PARAMETER Notes
Release notes text. Defaults to a one-line summary.

.EXAMPLE
./tools/release.ps1 -Version 0.1.1

.EXAMPLE
$env:HTTPS_PROXY = "http://host:port"
./tools/release.ps1 -Version 0.1.1 -Publish
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$Publish,
    [string]$Notes = ""
)

$ErrorActionPreference = "Stop"

# PowerShell 5.1 decides whether a native command's stderr is an error BEFORE
# the command runs, so `2>$null` and `2>&1 | Write-Verbose` do NOT prevent the
# NativeCommandError -- both were measured to throw anyway. The only reliable
# fix is to lower $ErrorActionPreference around the call itself. Every git/gh
# invocation therefore goes through Invoke-Native, and success is decided by
# the exit code, never by whether stderr happened to be non-empty.
function Invoke-Native {
    param([Parameter(Mandatory = $true)][scriptblock]$Command)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Command 2>&1 | ForEach-Object { Write-Verbose "$_" } }
    finally { $ErrorActionPreference = $previous }
    return $LASTEXITCODE
}

$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    $tag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $name = "qoder-guard-$tag"
    $dist = Join-Path $root "dist"
    $zip = Join-Path $dist "$name.zip"

    # The released version must match the declared metadata, or the tag and the
    # contents of the archive disagree. This drifted once (pyproject stayed at
    # 0.1.0 while v0.1.2 shipped), so it is checked, not trusted.
    $expected = $tag.TrimStart("v")
    $pyproject = Join-Path $root "pyproject.toml"
    $declared = (Select-String -Path $pyproject -Pattern '^version\s*=\s*"([^"]+)"' |
                 Select-Object -First 1).Matches[0].Groups[1].Value
    if ($declared -ne $expected) {
        throw "pyproject.toml declares version $declared but this release is $expected. Update pyproject.toml first."
    }

    $init = Join-Path $root "qoder_guard\__init__.py"
    $dunder = (Select-String -Path $init -Pattern '__version__\s*=\s*"([^"]+)"' |
               Select-Object -First 1).Matches[0].Groups[1].Value
    if ($dunder -ne $expected) {
        throw "qoder_guard/__init__.py declares __version__ $dunder but this release is $expected. Update it first."
    }

    # Refuse to package a dirty tree: the zip must match a commit exactly.
    $dirty = git status --porcelain
    if ($dirty) {
        throw "Working tree is dirty. Commit or stash first:`n$dirty"
    }

    # Refuse to reuse an existing tag. `rev-parse -q --verify` writes nothing to
    # stderr, but it still goes through the helper for consistency.
    $exists = Invoke-Native { git rev-parse -q --verify "refs/tags/$tag" > $null }
    if ($exists -eq 0) {
        throw "Tag $tag already exists. Bump the version or delete the tag."
    }

    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    if (Test-Path $zip) { Remove-Item $zip -Force }

    # Export tracked files only (git archive honours .gitignore and excludes .git).
    $code = Invoke-Native { git archive --format=zip --prefix="$name/" -o $zip HEAD }
    if ($code -ne 0) { throw "git archive failed" }

    $size = (Get-Item $zip).Length
    Write-Output ("packaged {0}  ({1} bytes)" -f $zip, $size)

    if (-not $Publish) {
        Write-Output "dry run: pass -Publish to tag, push, and create the release"
        return
    }

    $code = Invoke-Native { git tag -a $tag -m $tag }
    if ($code -ne 0) { throw "git tag failed (does $tag already exist?)" }

    $code = Invoke-Native { git push origin $tag }
    if ($code -ne 0) { throw "git push failed (is HTTPS_PROXY set?)" }

    if (-not $Notes) { $Notes = "Source archive for $tag." }
    $code = Invoke-Native { gh release create $tag $zip --title $tag --notes $Notes }
    if ($code -ne 0) { throw "gh release create failed" }

    Write-Output ("published release {0}" -f $tag)
}
finally {
    Pop-Location
}
