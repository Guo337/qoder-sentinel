"""Probe install.ps1: the one-command installer's contract.

The installer is the first thing a new user runs, so its failure modes matter
more than its happy path. This probe checks the parts that can be verified
without touching the machine: the file exists, parses as PowerShell, is pure
ASCII (a non-ASCII character would be mis-decoded under the GBK console), and
contains the behaviours the README promises.

It deliberately does NOT run the installer: doing so would register hooks in the
real user config and install packages. The script's runtime behaviour is covered
by the installer itself calling guard/verify_setup.py, and by
tools/_probe_project_install.py for the settings-mutation contract.

  1. install.ps1 exists at the repository root
  2. it parses as PowerShell with no syntax errors
  3. it is pure ASCII (no encoding hazard on a GBK console)
  4. it declares the documented parameters
  5. it supports both a local checkout and a release download
  6. it installs uv when missing, and fails loudly when it cannot
  7. it refreshes PATH after installing uv (new binaries are not on the
     inherited PATH)
  8. it registers the hooks and runs the self-check
  9. it never uses /MIR, which would delete audit_logs and .venv
 10. it judges native commands by exit code, not by stderr
 11. the README points at it

Run:  python tools/_probe_install_script.py   (exit 0 = pass)
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "install.ps1"
README = ROOT / "README.md"

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        FAILS.append(f"{name}: {detail}")


def main() -> int:
    # 1. the file is where the README will point
    check("script_exists", SCRIPT.is_file(), str(SCRIPT))
    if not SCRIPT.is_file():
        return report()

    text = SCRIPT.read_text(encoding="utf-8")

    # 2. parses as PowerShell. pythonnet is not a dependency, so the check is
    #    delegated to powershell.exe when available.
    import shutil
    import subprocess

    pwsh = shutil.which("powershell") or shutil.which("pwsh")
    if pwsh:
        probe = (
            "$e=$null;"
            f"$null=[System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}',[ref]$null,[ref]$e);"
            "if($e){$e | ForEach-Object {$_.Message}; exit 1}else{exit 0}"
        )
        proc = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", probe],
            capture_output=True, text=True,
        )
        check("parses_as_powershell", proc.returncode == 0,
              f"exit={proc.returncode} {proc.stdout.strip()[:200]}")
    else:
        # No PowerShell on PATH: fall back to a brace/quote balance sanity check.
        check("parses_as_powershell", text.count("{") == text.count("}"),
              "brace mismatch (PowerShell unavailable for a real parse)")

    # 3. pure ASCII
    non_ascii = [c for c in text if ord(c) > 127]
    check("pure_ascii", not non_ascii,
          f"{len(non_ascii)} non-ASCII char(s), first={non_ascii[:1]!r}")

    # 4. documented parameters
    for p in ("$Dir", "$Uninstall", "$NoVerify"):
        check(f"param_{p.lstrip('$')}", re.search(rf"\[[^\]]+\]{re.escape(p)}\b", text) is not None,
              f"{p} is not declared as a typed parameter")

    # 5. both sources are supported
    check("local_checkout_path", "PSScriptRoot" in text and "pyproject.toml" in text,
          "no local-checkout detection")
    check("release_download_path", "releases/latest" in text and "browser_download_url" in text,
          "no release download path")
    check("install_dir_default", "LOCALAPPDATA" in text,
          "no default install directory")

    # 6. uv bootstrap, and a loud failure when it cannot be done
    check("uv_bootstrap", "winget install --id astral-sh.uv" in text,
          "does not attempt to install uv")
    check("uv_failure_is_fatal", "Could not install uv automatically" in text,
          "missing uv does not stop the install")

    # 7. PATH refresh after installing uv
    check("path_refresh", "GetEnvironmentVariable(\"Path\", \"Machine\")" in text,
          "PATH is not refreshed after installing a new binary")

    # 8. registration and self-check
    check("registers_hooks", "guard\\install_hooks.py" in text, "never registers the hooks")
    check("runs_self_check", "guard\\verify_setup.py" in text, "never runs the self-check")
    check("uninstall_path", "--remove" in text, "no uninstall path")

    # 9. a mirror copy would delete audit_logs and .venv. Comments are stripped
    #    first so that a comment explaining WHY /MIR is avoided does not trip
    #    the check.
    code_lines = [
        ln for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    code = "\n".join(code_lines)
    check("no_mirror", "/MIR" not in code, "/MIR would delete audit_logs and .venv")

    # 10. stderr must not be treated as failure
    check("exit_code_judgement", "$LASTEXITCODE" in text, "does not judge native commands by exit code")
    check("error_preference_guard", "ErrorActionPreference" in text,
          "no guard against PowerShell 5.1 stderr handling")

    # 11. the README advertises it
    if README.is_file():
        readme = README.read_text(encoding="utf-8")
        check("readme_mentions_installer", "install.ps1" in readme,
              "README does not mention install.ps1")

    return report()


def report() -> int:
    if FAILS:
        print(f"FAILED ({len(FAILS)})")
        for f in FAILS:
            print("  -", f)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
