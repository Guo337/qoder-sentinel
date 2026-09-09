"""Install observation hooks into Qoder user-level config (~/.qoder-cn/settings.json).

This modifies Qoder CLI's own config, not VS Code. Steps:
  1. Back up existing settings.json -> settings.json.bak
  2. Generate hooks block based on settings/qoder.settings.json event structure and merge it in
Effect: qodercn sessions from any directory will have tool calls recorded to the audit log
(stage A records only, does not block).

WARNING: Paths are resolved to absolute paths at install time. If the project is
moved/renamed, the registered hook commands point to a script that no longer
exists, and the hook subprocess exits with code 2 -- which Qoder interprets as
"deny". The result is NOT a silent gap in monitoring: EVERY tool call is blocked
and the agent reports it cannot run any command (measured 2026-09-09 against
qoderclicn 1.1.45 using a throwaway --config-dir). Re-run this script after
moving the project.

Note on ${QODER_PROJECT_DIR}: the CLI does export this placeholder and
substitutes it in powershell-form commands, but it expands to the SESSION's cwd,
not to this project's root -- measured by registering
`uv run --project "${QODER_PROJECT_DIR}" python "${QODER_PROJECT_DIR}/guard/observe_hook.py"`
and launching Qoder from an unrelated directory (the hook was then looked up in
that unrelated directory). The placeholder therefore cannot make this
registration location-independent.

Usage:
  python guard/install_hooks.py           install/update hooks (uses current paths)
  python guard/install_hooks.py --check   self-check: are registered paths still valid
  python guard/install_hooks.py --remove  remove hooks (restore backup for full recovery)
"""
from __future__ import annotations

import json
import shlex
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "settings" / "qoder.settings.json"
USER_SETTINGS = Path.home() / ".qoder-cn" / "settings.json"
BACKUP = USER_SETTINGS.with_suffix(".json.bak")

# Hook entry script (absolute path, written to Qoder config at install time)
HOOK_SCRIPT = ROOT / "guard" / "observe_hook.py"


def _hook_command() -> str:
    """Generate the hook command registered in Qoder's config.

    The hook needs the tree-sitter grammar (structural command analysis), which
    lives in this project's `.venv`. Two options were measured (2026-09-08):

      A. `<venv>/Scripts/python.exe <script>`   fastest, but dies if `.venv`
         is deleted -- which is the normal outcome of the "keep it deletable"
         policy.
      B. `uv run --project <root> python <script>`   22ms slower per call, but
         uv REBUILDS the venv automatically when it is missing (measured: 1.3s
         once, then normal), and emits nothing on stdout, so the hook's JSON
         contract is unaffected.

    B is chosen: a monitoring hook that silently stops working after a routine
    `rm -rf .venv` is worse than one that costs 22ms. If uv itself is missing,
    the script falls back to the current interpreter and the guard degrades to
    regex-only mode (see qoder_guard/shell_ast.py).
    """
    script = HOOK_SCRIPT.as_posix()
    root = ROOT.as_posix()
    if shutil.which("uv"):
        return f'uv run --project "{root}" python "{script}"'
    return f"{Path(sys.executable).as_posix()} {script}"


def _build_hooks() -> dict:
    """Generate hooks based on template event list, substituting commands with current paths."""
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))["hooks"]
    cmd = _hook_command()
    built: dict = {}
    for event, groups in template.items():
        built[event] = []
        for group in groups:
            entries = []
            for h in group.get("hooks", []):
                entry = dict(h)
                if entry.get("type") == "command":
                    entry["command"] = cmd
                entries.append(entry)
            built[event].append({**group, "hooks": entries})
    return built


def _script_from_command(command: str) -> str:
    """Extract the hook script path from a registered command string.

    Two forms exist: a bare `<python> <script>` and
    `uv run --project "<root>" python "<script>"`. The root path can contain
    spaces, so the arguments are quoted and a naive split on whitespace takes
    the wrong piece -- use shlex, which understands the quoting.
    """
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        parts = command.split()
    for part in reversed(parts):
        if part.endswith(".py"):
            return part
    return parts[-1] if parts else ""


def check() -> int:
    """Self-check: whether the hook commands point to THIS project's script.

    Two failure modes are reported separately -- they share one fix but have
    very different consequences:

      MISSING    the registered script does not exist (project moved/renamed).
                 The hook subprocess exits with code 2, and Qoder reads exit
                 code 2 as "deny", so EVERY tool call is blocked (measured
                 2026-09-09 against qoderclicn 1.1.45).
      DIFFERENT  a valid script belonging to another copy of the project.
                 Monitoring runs, but it observes that other copy: edits made
                 here have no effect and audit state lands there.

    DIFFERENT must be checked here too, not only in verify_setup.py: the two
    checks used to disagree, so `--check` printed OK while the guard was in
    fact watching a different tree.
    """
    if not USER_SETTINGS.exists():
        print(f"[FAIL] User config not found: {USER_SETTINGS}")
        return 1
    data = json.loads(USER_SETTINGS.read_text(encoding="utf-8"))
    hooks = data.get("hooks") or {}
    if not hooks:
        print("[FAIL] No hooks in user config -- monitoring not installed")
        return 1

    missing: list[str] = []
    stale: list[str] = []
    print(f"User config: {USER_SETTINGS}")
    for event, groups in hooks.items():
        for group in groups:
            for h in group.get("hooks", []):
                cmd = h.get("command", "")
                script = _script_from_command(cmd)
                if not script:
                    missing.append(cmd)
                    flag = "NO-SCRIPT"
                elif not Path(script).exists():
                    missing.append(script)
                    flag = "MISSING"
                elif Path(script).resolve() != HOOK_SCRIPT.resolve():
                    stale.append(script)
                    flag = "DIFFERENT"
                else:
                    flag = "OK"
                print(f"  {event:22} {flag:9} {script}")
    if not missing and not stale:
        print("\n[OK] All hook paths valid, monitoring should work correctly")
        return 0
    if stale:
        print("\n[FAIL] Registration points at another copy of this project.")
        print("   Monitoring would observe that copy, not this one.")
    if missing:
        print("\n[FAIL] Registered hook script does not exist.")
        print("   Qoder reads the failed hook (exit 2) as 'deny', so every tool")
        print("   call is blocked until this is fixed.")
    print("   Fix: python guard/install_hooks.py  (re-register with current paths)")
    return 1


def main() -> int:
    if "--check" in sys.argv:
        return check()
    if not USER_SETTINGS.exists():
        print(f"[FAIL] User config not found: {USER_SETTINGS}")
        return 1
    if not TEMPLATE.exists():
        print(f"[FAIL] Template not found: {TEMPLATE}")
        return 1
    if not HOOK_SCRIPT.exists():
        print(f"[FAIL] Hook script not found: {HOOK_SCRIPT}")
        return 1

    # 1) Backup
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_ts = USER_SETTINGS.with_name(f"settings.json.bak-{ts}")
    shutil.copy2(USER_SETTINGS, backup_ts)
    shutil.copy2(USER_SETTINGS, BACKUP)  # Fixed-name backup for easy restoration
    print(f"[SAVED] Backed up -> {backup_ts.name}")

    # 2) Read existing + generate hooks with current paths
    data = json.loads(USER_SETTINGS.read_text(encoding="utf-8"))
    hooks = _build_hooks()

    if "--remove" in sys.argv:
        data.pop("hooks", None)
        action = "Remove hooks"
    else:
        data["hooks"] = hooks
        action = "Write hooks"

    # 3) Write back (keep original fields, only add/update hooks; uniform indent)
    USER_SETTINGS.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[OK] {action} complete: {USER_SETTINGS}")
    print(f"   Current top-level keys: {list(data.keys())}")
    print(f"   Hook command: {_hook_command()}")
    print("   Restore: copy the .bak with same name back to settings.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
