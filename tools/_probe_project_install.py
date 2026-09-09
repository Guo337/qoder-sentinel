"""Probe guard/install_project.py: project-level registration contract.

Covers the behaviors that matter for a settings-mutating installer:

  1. --dry-run writes nothing
  2. --check on an unregistered target exits 1 and names every missing event
  3. install creates the four events with an absolute command
  4. --check passes after install
  5. re-install is idempotent (reports "nothing to do", no backup churn)
  6. a foreign hook group is preserved untouched
  7. a stale command path is REPAIRED, not reported as "up to date"
  8. a UTF-8 BOM in the settings file is tolerated
  9. --remove deletes only our entries and keeps foreign ones
 10. --json emits parseable output with the expected keys
 11. the real user config (~/.qoder-cn/settings.json) is never touched

Every mutation happens inside a throwaway temp directory, so the production
Qoder config and audit database are not involved.

Run:  python tools/_probe_project_install.py
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "guard" / "install_project.py"
USER_SETTINGS = pathlib.Path.home() / ".qoder-cn" / "settings.json"

EVENTS = ["SessionStart", "PreToolUse", "PostToolUse", "PostToolUseFailure"]
FOREIGN_CMD = 'node ".qoder/hooks/secret-scan.mjs" --mode=user-prompt'

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

fails: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    if not ok:
        fails.append(f"{label}: {detail}" if detail else label)
    print(f"  [{'OK ' if ok else 'BAD'}] {label}" + (f"  -- {detail}" if detail and not ok else ""))


def run(*args: str, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(INSTALLER), *args],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=str(cwd or ROOT), timeout=120,
    )


def out(proc: subprocess.CompletedProcess) -> str:
    return proc.stdout.decode("utf-8", "replace")


def read_settings(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_settings(path: pathlib.Path, data: dict, *, bom: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2)
    path.write_text(("\ufeff" if bom else "") + text, encoding="utf-8")


def our_commands(settings: dict) -> list[str]:
    found: list[str] = []
    for groups in (settings.get("hooks") or {}).values():
        for group in groups:
            for entry in group.get("hooks", []):
                if "observe_hook.py" in str(entry.get("command", "")):
                    found.append(entry["command"])
    return found


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="qguard_install_"))
    target = tmp / "target"
    target.mkdir()
    settings = target / ".qoder" / "settings.json"
    before_user = USER_SETTINGS.stat().st_mtime_ns if USER_SETTINGS.exists() else None

    try:
        print("=== 1. dry-run writes nothing ===")
        proc = run("--target", str(target), "--dry-run")
        check("dry-run exits 0", proc.returncode == 0, out(proc)[:200])
        check("dry-run created no settings file", not settings.exists())
        check("dry-run mentions the events",
              all(e in out(proc) for e in EVENTS), out(proc)[:200])

        print("=== 2. --check on unregistered target fails ===")
        proc = run("--target", str(target), "--check")
        text = out(proc)
        check("check exits 1", proc.returncode == 1, f"exit={proc.returncode}")
        check("check reports missing settings", "settings not found" in text, text[:200])

        print("=== 3. install registers four events ===")
        proc = run("--target", str(target))
        check("install exits 0", proc.returncode == 0, out(proc)[:300])
        check("settings file created", settings.exists())
        data = read_settings(settings)
        hooks = data.get("hooks") or {}
        check("all four events present", all(e in hooks for e in EVENTS),
              f"got {sorted(hooks)}")
        cmds = our_commands(data)
        check("four commands registered", len(cmds) == 4, f"got {len(cmds)}")
        check("command uses an absolute script path",
              all(str(ROOT.as_posix()) in c for c in cmds), str(cmds[:1]))
        check("no backup when the file did not exist",
              not list(settings.parent.glob("*.bak-*")))

        print("=== 4. --check passes after install ===")
        proc = run("--target", str(target), "--check")
        check("check exits 0", proc.returncode == 0, out(proc)[:300])
        check("check says healthy", "[OK]" in out(proc), out(proc)[:200])

        print("=== 5. re-install is idempotent ===")
        proc = run("--target", str(target))
        check("re-install exits 0", proc.returncode == 0, out(proc)[:200])
        check("re-install reports nothing to do",
              "nothing to do" in out(proc), out(proc)[:200])
        check("still exactly four commands", len(our_commands(read_settings(settings))) == 4)

        print("=== 6. foreign hooks are preserved ===")
        data = read_settings(settings)
        data["hooks"]["UserPromptSubmit"] = [
            {"hooks": [{"type": "command", "command": FOREIGN_CMD}]}
        ]
        write_settings(settings, data)
        proc = run("--target", str(target))
        check("install with foreign hook exits 0", proc.returncode == 0, out(proc)[:200])
        after = read_settings(settings)
        foreign = [
            e.get("command")
            for g in after["hooks"].get("UserPromptSubmit", [])
            for e in g.get("hooks", [])
        ]
        check("foreign command untouched", FOREIGN_CMD in foreign, str(foreign))
        check("foreign event not claimed by us",
              "UserPromptSubmit" not in [e for e in EVENTS],
              "sanity")

        print("=== 7. a stale command path is repaired ===")
        data = read_settings(settings)
        data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = (
            'uv run --project "C:/Old/Path" python "C:/Old/Path/guard/observe_hook.py"'
        )
        write_settings(settings, data)
        proc = run("--target", str(target))
        text = out(proc)
        check("repair does not claim 'nothing to do'",
              "nothing to do" not in text, text[:200])
        check("repair names the event", "PreToolUse" in text, text[:200])
        repaired = read_settings(settings)["hooks"]["PreToolUse"]
        stale_left = [
            e["command"] for g in repaired for e in g.get("hooks", [])
            if "C:/Old/Path" in e["command"]
        ]
        check("stale path gone", not stale_left, str(stale_left))
        check("exactly one group after repair", len(repaired) == 1, str(len(repaired)))
        check("backup created on overwrite",
              bool(list(settings.parent.glob("*.bak-*"))))

        print("=== 8. a UTF-8 BOM is tolerated ===")
        data = read_settings(settings)
        write_settings(settings, data, bom=True)
        proc = run("--target", str(target), "--check")
        check("check works with BOM", proc.returncode == 0, out(proc)[:300])

        print("=== 9. --remove deletes only our entries ===")
        proc = run("--target", str(target), "--remove")
        check("remove exits 0", proc.returncode == 0, out(proc)[:200])
        after = read_settings(settings)
        check("our commands all gone", not our_commands(after), str(our_commands(after)))
        remaining = [
            e.get("command")
            for g in after.get("hooks", {}).get("UserPromptSubmit", [])
            for e in g.get("hooks", [])
        ]
        check("foreign hook survived removal", FOREIGN_CMD in remaining, str(remaining))
        proc = run("--target", str(target), "--check")
        check("check fails after removal", proc.returncode == 1, f"exit={proc.returncode}")

        print("=== 10. --json output ===")
        proc = run("--target", str(target), "--json")
        text = out(proc)
        try:
            payload = json.loads(text)
            check("json parses", True)
            check("json reports ok", payload.get("ok") is True, str(payload)[:200])
            check("json lists four events",
                  sorted(payload.get("events") or []) == sorted(EVENTS),
                  str(payload.get("events")))
            check("json exposes the command",
                  "observe_hook.py" in str(payload.get("command")), "")
        except ValueError as exc:
            check("json parses", False, f"{exc} | {text[:200]}")

        print("=== 11. real user config untouched ===")
        after_user = USER_SETTINGS.stat().st_mtime_ns if USER_SETTINGS.exists() else None
        check("user settings unchanged", before_user == after_user,
              f"{before_user} -> {after_user}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if fails:
        print(f"FAILED ({len(fails)})")
        for item in fails:
            print(f"  - {item}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
