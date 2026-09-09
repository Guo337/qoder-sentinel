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

$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    $tag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $name = "qoder-guard-$tag"
    $dist = Join-Path $root "dist"
    $zip = Join-Path $dist "$name.zip"

    # Refuse to package a dirty tree: the zip must match a commit exactly.
    $dirty = git status --porcelain
    if ($dirty) {
        throw "Working tree is dirty. Commit or stash first:`n$dirty"
    }

    # Refuse to reuse an existing tag.
    git rev-parse -q --verify "refs/tags/$tag" > $null
    if ($LASTEXITCODE -eq 0) {
        throw "Tag $tag already exists. Bump the version or delete the tag."
    }

    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    if (Test-Path $zip) { Remove-Item $zip -Force }

    # Export tracked files only (git archive honours .gitignore and excludes .git).
    git archive --format=zip --prefix="$name/" -o $zip HEAD
    if ($LASTEXITCODE -ne 0) { throw "git archive failed" }

    $size = (Get-Item $zip).Length
    Write-Output ("packaged {0}  ({1} bytes)" -f $zip, $size)

    if (-not $Publish) {
        Write-Output "dry run: pass -Publish to tag, push, and create the release"
        return
    }

    git tag -a $tag -m $tag
    if ($LASTEXITCODE -ne 0) { throw "git tag failed" }

    git push origin $tag
    if ($LASTEXITCODE -ne 0) { throw "git push failed (is HTTPS_PROXY set?)" }

    if (-not $Notes) { $Notes = "Source archive for $tag." }
    gh release create $tag $zip --title $tag --notes $Notes
    if ($LASTEXITCODE -ne 0) { throw "gh release create failed" }

    Write-Output ("published release {0}" -f $tag)
}
finally {
    Pop-Location
}
