<#
.SYNOPSIS
    Install qoder-sentinel and register its Qoder hooks.

.DESCRIPTION
    One command to go from nothing to a registered, self-checked guard.

    If the script sits next to pyproject.toml it treats that directory as a
    checkout and installs in place. Otherwise it downloads the latest GitHub
    release archive into the install directory and installs there.

    The hooks are registered in the user config (~/.qoder-cn/settings.json), so
    every qodercn session is covered regardless of the working directory.

    Re-running the script is safe: it refreshes the files and re-registers the
    hooks, which is also how an upgrade is performed.

.PARAMETER Dir
    Install directory. Defaults to %LOCALAPPDATA%\qoder-sentinel when there is
    no local checkout to use.

.PARAMETER Uninstall
    Remove the registered hooks instead of installing.

.PARAMETER NoVerify
    Skip the post-install self-check (guard\verify_setup.py).

.PARAMETER NoRegister
    Install the files but do not touch the user-level hook config. Use this when
    you only want the files (for example to register a single project with
    guard\install_project.py instead).

.PARAMETER Shortcut
    Also create a desktop shortcut that opens the audit panel. The shortcut
    starts the panel with pythonw.exe, so no console window appears behind it.

.PARAMETER StartMenu
    Also create a Start menu shortcut that opens the audit panel.

.EXAMPLE
    irm https://raw.githubusercontent.com/Guo337/qoder-sentinel/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Dir "D:\tools\qoder-sentinel"

.EXAMPLE
    .\install.ps1 -Shortcut -StartMenu

.EXAMPLE
    .\install.ps1 -Uninstall
#>
[CmdletBinding()]
# Write-Host is deliberate: this is an interactive installer whose coloured
# progress output is the product. Write-Output would put it on the pipeline and
# drop the colour.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingWriteHost', '',
    Justification = 'Interactive installer; coloured console output is intended.')]
param(
    [string]$Dir = "",
    [switch]$Uninstall,
    [switch]$NoVerify,
    [switch]$NoRegister,
    [switch]$Shortcut,
    [switch]$StartMenu
)

$ErrorActionPreference = "Stop"

$RepoSlug = "Guo337/qoder-sentinel"

# The shortcut is named once so creation and removal cannot drift apart.
$ShortcutName = "Qoder Sentinel Audit.lnk"

# PowerShell 5.1 decides whether a native command's stderr is an error BEFORE
# the command runs, so 2>$null does not suppress it. uv writes progress lines to
# stderr, which would abort the script. Lower the preference around the call and
# judge success by the exit code only.
function Invoke-Native {
    param([Parameter(Mandatory = $true)][scriptblock]$Command)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Command 2>&1 | ForEach-Object { Write-Verbose "$_" } }
    finally { $ErrorActionPreference = $previous }
    return $LASTEXITCODE
}

function Fail {
    param([string]$Message)
    Write-Host ""
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Info {
    param([string]$Message)
    Write-Host "    $Message"
}

# A getter rather than an Update- function: Update is treated as state
# changing, which would require ShouldProcess support. Reading the value and
# letting the caller assign keeps the analyzer quiet without adding a
# confirmation prompt nobody wants here.
function Get-FreshPath {
    return [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
           [Environment]::GetEnvironmentVariable("Path", "User")
}

# pythonw.exe runs without a console window, which is what a GUI shortcut wants.
# Falls back to nothing when the environment has not been created yet, so the
# caller can skip the shortcut instead of creating a broken one.
function Get-WindowlessPython {
    param([Parameter(Mandatory = $true)][string]$InstallDir)
    $candidate = Join-Path $InstallDir ".venv\Scripts\pythonw.exe"
    if (Test-Path $candidate) { return $candidate }
    return $null
}

# "New-" is on the ShouldProcess list, so this uses "Register-" instead: the
# meaning is the same here and no confirmation prompt is wanted.
function Register-GuardShortcut {
    param(
        [Parameter(Mandatory = $true)][string]$Folder,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$InstallDir
    )
    if (-not (Test-Path $Folder)) {
        New-Item -ItemType Directory -Force -Path $Folder | Out-Null
    }
    $link = Join-Path $Folder $ShortcutName
    $shell = New-Object -ComObject WScript.Shell
    # Not named $shortcut: PowerShell is case insensitive and the caller has a
    # -Shortcut switch of its own.
    $lnk = $shell.CreateShortcut($link)
    $lnk.TargetPath = $Target
    $lnk.Arguments = "`"$InstallDir\guard\audit_gui.py`""
    $lnk.WorkingDirectory = $InstallDir
    $lnk.IconLocation = "$env:SystemRoot\System32\shell32.dll,167"
    $lnk.Description = "Qoder Sentinel audit panel"
    $lnk.Save()
    return $link
}

# Both shortcut locations are looked up the same way, so removal finds whatever
# creation made regardless of the language of the OS.
function Get-ShortcutFolder {
    return @(
        [Environment]::GetFolderPath("Desktop"),
        [Environment]::GetFolderPath("Programs")
    )
}

Write-Host ""
Write-Host "qoder-sentinel installer" -ForegroundColor White
Write-Host ""

# ---------------------------------------------------------------- source tree

$localCheckout = $null
if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "pyproject.toml"))) {
    $localCheckout = $PSScriptRoot
}

if ($Dir) {
    $installDir = [System.IO.Path]::GetFullPath($Dir)
} elseif ($localCheckout) {
    $installDir = $localCheckout
} else {
    $installDir = Join-Path $env:LOCALAPPDATA "qoder-sentinel"
}

# Nothing to copy when the files are already at the destination.
$inPlace = $localCheckout -and
           ($installDir.TrimEnd('\') -eq $localCheckout.TrimEnd('\'))

# ------------------------------------------------------------------ uninstall

if ($Uninstall) {
    Step "Uninstall"
    if (-not (Test-Path (Join-Path $installDir "guard\install_hooks.py"))) {
        Fail "No installation found at $installDir. Pass -Dir to point at it."
    }
    Push-Location $installDir
    try {
        $code = Invoke-Native { uv run python "guard\install_hooks.py" --remove }
        if ($code -ne 0) { Fail "Removing the hooks failed (exit $code)." }
    } finally { Pop-Location }

    $removed = 0
    foreach ($folder in Get-ShortcutFolder) {
        $link = Join-Path $folder $ShortcutName
        if (Test-Path $link) {
            Remove-Item $link -Force
            $removed++
        }
    }
    if ($removed -gt 0) { Info "removed $removed shortcut(s)" }

    Write-Host ""
    Write-Host "Hooks removed. The files in $installDir are untouched." -ForegroundColor Green
    Write-Host "Delete that directory to remove them too." -ForegroundColor Green
    exit 0
}

# ----------------------------------------------------------- 1. source files

Step "1/5  Preparing files"
Info "install directory: $installDir"

if ($inPlace) {
    Info "source: current checkout (in place)"
} elseif ($localCheckout) {
    Info "source: current checkout (copying)"
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    # robocopy without /MIR: files are refreshed, anything extra already there
    # (audit_logs, .venv) is left alone. Exit codes 0-7 are success.
    $rc = Invoke-Native {
        robocopy $localCheckout $installDir /E /NFL /NDL /NJH /NJS /NP `
            /XD ".git" ".venv" "audit_logs" "__pycache__" ".qoder"
    }
    if ($rc -ge 8) { Fail "Copying the files failed (robocopy exit $rc)." }
    Info "files copied"
} else {
    Info "source: latest GitHub release"
    try {
        $release = Invoke-RestMethod `
            -Uri "https://api.github.com/repos/$RepoSlug/releases/latest" `
            -Headers @{ "User-Agent" = "qoder-sentinel-installer" } `
            -UseBasicParsing
    } catch {
        Fail ("Could not reach the GitHub API: $($_.Exception.Message)`n" +
              "      If the network needs a proxy, set HTTPS_PROXY first, e.g.`n" +
              "      `$env:HTTPS_PROXY = 'http://host:port'")
    }

    $asset = $release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
    if (-not $asset) { Fail "Release $($release.tag_name) has no zip asset." }
    Info "release: $($release.tag_name)"

    $stamp = [guid]::NewGuid().ToString("N")
    $tmpZip = Join-Path $env:TEMP "qoder-sentinel-$stamp.zip"
    $tmpDir = Join-Path $env:TEMP "qoder-sentinel-$stamp"
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tmpZip -UseBasicParsing
        Expand-Archive -Path $tmpZip -DestinationPath $tmpDir -Force
    } catch {
        Fail "Downloading or extracting the release failed: $($_.Exception.Message)"
    }

    $inner = Get-ChildItem $tmpDir -Directory | Select-Object -First 1
    if (-not $inner) { Fail "The release archive has no top-level directory." }

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    # robocopy without /MIR: files are refreshed, anything extra already there
    # (audit_logs, .venv) is left alone. Exit codes 0-7 are success.
    $rc = Invoke-Native { robocopy $inner.FullName $installDir /E /NFL /NDL /NJH /NJS /NP }
    if ($rc -ge 8) { Fail "Copying the files failed (robocopy exit $rc)." }

    Remove-Item $tmpZip, $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Info "files copied"
}

if (-not (Test-Path (Join-Path $installDir "pyproject.toml"))) {
    Fail "$installDir does not look like a qoder-sentinel tree (no pyproject.toml)."
}

# --------------------------------------------------------------------- 2. uv

Step "2/5  Checking uv"

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "    uv is required and was not found." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "    Installing it with winget..." -ForegroundColor Yellow
        $rc = Invoke-Native {
            winget install --id astral-sh.uv --exact --silent `
                --accept-source-agreements --accept-package-agreements
        }
        $env:Path = Get-FreshPath
        if ($rc -ne 0 -or -not (Get-Command uv -ErrorAction SilentlyContinue)) {
            Fail "Could not install uv automatically. Install it from https://docs.astral.sh/uv/ and re-run."
        }
    } else {
        Fail "Install uv from https://docs.astral.sh/uv/ and re-run (winget was not available either)."
    }
}
Info "uv $((& uv --version))"

# ---------------------------------------------------- 3. environment + hooks

Step "3/5  Creating the environment"
Push-Location $installDir
try {
    $code = Invoke-Native { uv sync }
    if ($code -ne 0) { Fail "uv sync failed (exit $code)." }
    Info "environment ready"
} finally { Pop-Location }

if ($NoRegister) {
    Step "4/5  Registration skipped (-NoRegister)"
    Info "register later with: uv run python guard\install_hooks.py"
} else {
    Step "4/5  Registering the hooks"
    Push-Location $installDir
    try {
        $code = Invoke-Native { uv run python "guard\install_hooks.py" }
        if ($code -ne 0) { Fail "Registering the hooks failed (exit $code)." }
    } finally { Pop-Location }
}

# ------------------------------------------------------------------ 5. verify

if ($NoRegister) {
    # The self-check starts with the registration check, which would fail by
    # design here, so it is skipped rather than reported as a broken install.
    Step "5/5  Self-check skipped (nothing was registered)"
} elseif ($NoVerify) {
    Step "5/5  Self-check skipped (-NoVerify)"
} else {
    Step "5/5  Self-check"
    Push-Location $installDir
    try {
        $code = Invoke-Native { uv run python "guard\verify_setup.py" }
        if ($code -ne 0) {
            Fail "The self-check reported a problem (exit $code). Run it directly to see the details."
        }
    } finally { Pop-Location }
}

# -------------------------------------------------------------------- summary

# Shortcuts are opt in. A shortcut is only useful when it can start the panel
# without a console window, so it is skipped (with a reason) when pythonw.exe
# is missing -- that happens with -NoRegister, because uv sync may not have run.
$shortcutTarget = Get-WindowlessPython -InstallDir $installDir
if ($Shortcut -or $StartMenu) {
    Step "Shortcuts"
    if (-not $shortcutTarget) {
        Info "skipped: no .venv\Scripts\pythonw.exe yet (run the installer without -NoRegister)"
    } else {
        $folders = @()
        if ($Shortcut) { $folders += [Environment]::GetFolderPath("Desktop") }
        if ($StartMenu) { $folders += [Environment]::GetFolderPath("Programs") }
        foreach ($folder in $folders) {
            $link = Register-GuardShortcut -Folder $folder -Target $shortcutTarget -InstallDir $installDir
            Info $link
        }
    }
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host ""
Write-Host "  Installed at : $installDir"
if ($NoRegister) {
    Write-Host "  Registered   : no (-NoRegister was set)"
} else {
    Write-Host "  Registered   : ~/.qoder-cn/settings.json (user level, all sessions)"
}
Write-Host ""
Write-Host "  Blocking is off by default (observation only). To enable it:"
Write-Host "    `$env:QGUARD_BLOCK = '1'"
Write-Host ""
if (-not $NoRegister) {
    Write-Host "  Check the registration at any time:"
    Write-Host "    uv run --project `"$installDir`" python `"$installDir\guard\install_hooks.py`" --check"
    Write-Host ""
}
Write-Host "  If the directory is moved or renamed, re-run this installer."
Write-Host ""
