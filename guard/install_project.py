"""Install this guard into ANOTHER project as a project-level Qoder hook.

The user-level installer (guard/install_hooks.py) registers hooks in
`~/.qoder-cn/settings.json`, so every Qoder session on this machine is audited
by THIS checkout. This installer does the opposite: it registers hooks in
`<target>/.qoder/settings.json`, so a different project is audited by the guard
that lives in THIS checkout.

Why project-level is safe here
------------------------------
`guard/observe_hook.py` derives the project root from its own resolved path
(`Path(__file__).resolve().parent.parent`), never from the session cwd. So the
audit state always lands in the checkout that owns the hook, regardless of
which directory Qoder was launched from. Verified 2026-09-09: launching Qoder
from an unrelated directory still produced audit rows in this project.

Why the command is an absolute path
-----------------------------------
Qoder expands `${QODER_PROJECT_DIR}` to the SESSION cwd, not to the project that
owns the settings file (measured 2026-09-09 against qoderclicn 1.1.45). A
relative `python guard/observe_hook.py` therefore breaks as soon as Qoder is
launched from elsewhere. Absolute paths are the only form that survives.

Failure mode worth knowing
--------------------------
If this checkout is moved or deleted, the registered command points at a script
that no longer exists. The hook subprocess then exits with code 2, which Qoder
reads as "deny" -- EVERY tool call in the target project is blocked. Run
`--check` after moving anything, and `--remove` to unregister.

Hook commands are executed by Git Bash, so `uv`/`python` must be on the BASH
PATH, not just the PowerShell one.

Usage:
  python guard/install_project.py --target <project>            install/update
  python guard/install_project.py --target <project> --check    report drift (exit 1 if any)
  python guard/install_project.py --target <project> --dry-run  print plan, write nothing
  python guard/install_project.py --target <project> --json     machine-readable output
  python guard/install_project.py --target <project> --remove   unregister our entries only
"""
from __future__ import annotations

import json
import shlex
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK_SCRIPT = ROOT / "guard" / "observe_hook.py"

# Event -> matcher, matching settings/qoder.settings.json (all tools).
EVENTS: dict[str, str] = {
    "SessionStart": "*",
    "PreToolUse": "*",
    "PostToolUse": "*",
    "PostToolUseFailure": "*",
}

# A hook entry belongs to this guard when its command references this script
# name. Used both to replace stale entries and to leave foreign hooks alone.
MARKER = "observe_hook.py"


def _hook_command() -> str:
    """Absolute hook command, preferring `uv run` for its venv auto-rebuild.

    Same trade-off as guard/install_hooks.py (measured 2026-09-08): a direct
    interpreter path is ~22ms faster but dies silently if `.venv` is deleted;
    `uv run` rebuilds it automatically and prints nothing on stdout, so the
    hook's JSON contract on stdout stays clean.
    """
    script = HOOK_SCRIPT.as_posix()
    root = ROOT.as_posix()
    if shutil.which("uv"):
        return f'uv run --project "{root}" python "{script}"'
    return f"{Path(sys.executable).as_posix()} {script}"


def _script_from_command(command: str) -> str:
    """Extract the hook script path, honoring quoting (paths contain spaces)."""
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        parts = command.split()
    for part in reversed(parts):
        if part.endswith(".py"):
            return part
    return parts[-1] if parts else ""


def _is_ours(entry: dict) -> bool:
    return MARKER in str(entry.get("command", ""))


def _read_json(path: Path) -> dict:
    """Parse a JSON settings file, tolerating a UTF-8 BOM.

    Editors and `Set-Content -Encoding UTF8` (Windows PowerShell 5.1) prepend a
    BOM, which `json.loads` rejects with "Unexpected UTF-8 BOM". Qoder itself
    writes no BOM, but a settings file may well have been hand-edited -- a
    crash here would be a confusing failure for the user, so accept both.
    """
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _desired_events(command: str) -> dict[str, list[dict]]:
    """Build the hook groups to merge, one per event."""
    return {
        event: [{"matcher": matcher, "hooks": [{"type": "command", "command": command}]}]
        for event, matcher in EVENTS.items()
    }


def _merge(hooks: dict, desired: dict[str, list[dict]]) -> tuple[dict, list[str]]:
    """Merge our groups into an existing hooks block.

    Foreign groups (any entry not referencing our script) are preserved
    untouched. For an event we manage, our old group is replaced wholesale so a
    changed command path cannot accumulate duplicates.

    `touched` lists every event whose resulting value differs from the input --
    including events that already existed but whose command path went stale
    (e.g. the checkout was moved). Reporting only newly-added events would make
    the installer print "already up to date" while leaving a dead path in place.
    """
    merged: dict = {}
    for event, groups in hooks.items():
        if event not in desired:
            merged[event] = groups
            continue
        kept = [
            group
            for group in groups
            if not any(_is_ours(h) for h in group.get("hooks", []))
        ]
        merged[event] = kept + desired[event]
    for event, groups in desired.items():
        if event not in hooks:
            merged[event] = groups
    touched = [event for event, value in merged.items() if value != hooks.get(event)]
    return merged, touched


def _remove(hooks: dict) -> tuple[dict, list[str]]:
    """Drop our entries, keep everything else. Returns the events we touched."""
    result: dict = {}
    removed: list[str] = []
    for event, groups in hooks.items():
        kept = [
            group
            for group in groups
            if not any(_is_ours(h) for h in group.get("hooks", []))
        ]
        if kept:
            result[event] = kept
        if len(kept) != len(groups):
            removed.append(event)
    return result, removed


def _drift(settings: Path, command: str) -> list[str]:
    """Report why the registration would not work, without writing anything."""
    problems: list[str] = []
    if not HOOK_SCRIPT.exists():
        problems.append(f"hook script missing: {HOOK_SCRIPT}")
    if not settings.exists():
        problems.append(f"settings not found: {settings}")
        return problems
    try:
        data = _read_json(settings)
    except (OSError, ValueError) as exc:
        problems.append(f"settings unreadable: {exc}")
        return problems

    hooks = data.get("hooks") or {}
    for event in EVENTS:
        groups = hooks.get(event) or []
        ours = [
            h
            for group in groups
            for h in group.get("hooks", [])
            if _is_ours(h)
        ]
        if not ours:
            problems.append(f"{event}: not registered")
            continue
        for entry in ours:
            registered = _script_from_command(str(entry.get("command", "")))
            if not registered:
                problems.append(f"{event}: command has no script path")
            elif not Path(registered).exists():
                problems.append(
                    f"{event}: registered script does not exist: {registered}"
                )
            elif Path(registered).resolve() != HOOK_SCRIPT.resolve():
                problems.append(
                    f"{event}: registered script belongs to another checkout: "
                    f"{registered}"
                )
            elif str(entry.get("command", "")) != command:
                problems.append(
                    f"{event}: command differs from current installer output"
                )
    return problems


def _write_settings(settings: Path, data: dict, dry_run: bool) -> str | None:
    """Back up then write. Returns the backup filename, or None when dry-running."""
    if dry_run:
        return None
    settings.parent.mkdir(parents=True, exist_ok=True)
    backup_name: str | None = None
    if settings.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = settings.with_name(f"settings.json.bak-{stamp}")
        shutil.copy2(settings, backup)
        backup_name = backup.name
    settings.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return backup_name


def _parse_args(argv: list[str]) -> dict:
    opts: dict = {"target": Path.cwd()}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--check":
            opts["check"] = True
        elif arg == "--dry-run":
            opts["dry_run"] = True
        elif arg == "--json":
            opts["json"] = True
        elif arg == "--remove":
            opts["remove"] = True
        elif arg.startswith("--target="):
            opts["target"] = Path(arg.split("=", 1)[1])
        elif arg == "--target":
            i += 1
            if i >= len(argv):
                raise SystemExit("--target needs a path")
            opts["target"] = Path(argv[i])
        else:
            raise SystemExit(f"unknown argument: {arg}")
        i += 1
    return opts


def main(argv: list[str] | None = None) -> int:
    opts = _parse_args(list(sys.argv[1:] if argv is None else argv))
    target = Path(opts["target"]).expanduser().resolve()
    settings = target / ".qoder" / "settings.json"
    command = _hook_command()
    as_json = bool(opts.get("json"))

    if opts.get("check"):
        problems = _drift(settings, command)
        if as_json:
            print(json.dumps({
                "ok": not problems,
                "action": "check",
                "target": str(target),
                "settingsPath": str(settings),
                "expectedCommand": command,
                "problems": problems,
            }, ensure_ascii=False, indent=2))
        else:
            print(f"Target:   {target}")
            print(f"Settings: {settings}")
            print(f"Command:  {command}")
            if problems:
                print("\n[FAIL] registration is not healthy:")
                for item in problems:
                    print(f"  - {item}")
                print("\n  Fix: python guard/install_project.py --target "
                      f'"{target}"')
            else:
                print("\n[OK] registration healthy")
        return 1 if problems else 0

    if not HOOK_SCRIPT.exists():
        print(f"[FAIL] hook script not found: {HOOK_SCRIPT}")
        return 1
    if not target.is_dir():
        print(f"[FAIL] target is not a directory: {target}")
        return 1

    data: dict = {}
    if settings.exists():
        try:
            data = _read_json(settings)
        except (OSError, ValueError) as exc:
            print(f"[FAIL] cannot parse {settings}: {exc}")
            return 1
    hooks = data.get("hooks") or {}

    if opts.get("remove"):
        new_hooks, touched = _remove(hooks)
        action = "remove"
    else:
        new_hooks, touched = _merge(hooks, _desired_events(command))
        action = "install"

    if new_hooks:
        data["hooks"] = new_hooks
    else:
        data.pop("hooks", None)

    dry_run = bool(opts.get("dry_run"))
    backup = _write_settings(settings, data, dry_run) if touched else None

    if as_json:
        print(json.dumps({
            "ok": True,
            "action": action,
            "dryRun": dry_run,
            "target": str(target),
            "settingsPath": str(settings),
            "command": command,
            "events": touched,
            "backup": backup,
            "guardRoot": str(ROOT),
        }, ensure_ascii=False, indent=2))
        return 0

    if not touched:
        print(f"[OK] nothing to do: {settings} already has no entries of ours"
              if opts.get("remove")
              else f"[OK] nothing to do: {settings} already up to date")
        return 0

    verb = "Would write" if dry_run else "Wrote"
    print(f"{verb}: {settings}")
    print(f"  action: {action} ({', '.join(touched)})")
    print(f"  command: {command}")
    print(f"  guard root: {ROOT}")
    if backup:
        print(f"  backup: {backup}")
    if not dry_run:
        if action == "remove":
            print("\n  Unregistered. Foreign hooks in this file were left alone.")
            print("  Re-install: python guard/install_project.py --target "
                  f'"{target}"')
        else:
            print("\n  Next: qodercn in that project will now audit via this guard.")
            print("  Verify: python guard/install_project.py --target "
                  f'"{target}" --check')
            print("  Undo:   python guard/install_project.py --target "
                  f'"{target}" --remove')
    return 0


if __name__ == "__main__":
    sys.exit(main())
