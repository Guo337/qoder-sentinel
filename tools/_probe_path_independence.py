"""Regression test: the hook must work from ANY location and ANY cwd.

A hook is invoked by an external program, so it cannot assume anything about
the current working directory. It must also survive the project being moved,
renamed, or cloned somewhere else -- that portability is what makes the repo
usable as an open-source distribution.

What is verified (against a COPY of the project, never the original):

  1. no machine-specific paths -- no source file hardcodes an absolute path
                                  from the author's machine (checked statically)
  2. cwd independence         -- the hook runs from the project root, the
                                  parent directory, and an unrelated temp dir
  3. slash styles             -- invoked with backslashes, forward slashes and a
                                  MIXED form. The mixed form is the regression
                                  case: the old `__file__.rsplit("\\", 2)[0]`
                                  bootstrap returned "C:" for a mixed path and
                                  then silently depended on cwd.
  4. path shapes              -- the copy lives under a path containing a space
                                  and a non-ASCII character
  5. state follows the code   -- the hook writes its audit db inside the copy,
                                  not inside the original project

Run:  uv run --project . python tools/_probe_path_independence.py
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK_REL = Path("guard") / "observe_hook.py"

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# The hook needs its runtime dependencies, so invoke it through uv exactly the
# way the registered hook command does. `--project <copy>` makes uv build the
# environment inside the copy, which is what we want to exercise.
UV = "uv"

# Directories that must never be copied into the sandbox: large, machine
# specific, or they would defeat the point of the test.
SKIP_DIRS = {".git", ".venv", "__pycache__", "audit_logs",
             ".pytest_cache", ".mypy_cache", ".ruff_cache"}

# An absolute path that embeds a user/host name, ANYWHERE on the line. The
# captured group is the account name; it is a hit unless that name is a known
# placeholder used in documentation.
#
# This deliberately does NOT require a quote before the path. The earlier
# pattern did, and therefore missed the very case it was written for: a
# command payload like `rm -rf C:\\Users\\<account>\\temp` has the path in the
# MIDDLE of a string literal, so three real occurrences survived a "clean"
# scan. An exemption (the placeholder whitelist) must always be re-tested
# against a counter-example.
_ABS_PATH_RE = re.compile(
    r"""(?:[A-Za-z]:[\\/]Users[\\/]|/(?:home|Users)/|\\\\[A-Za-z0-9_.-]+[\\/])
        ([A-Za-z0-9_.-]+)""",
    re.VERBOSE,
)

# Placeholder account names used in documentation examples and self-tests. A
# path built from one of these documents a format, it is not a machine path.
_PLACEHOLDER_USERS = {"name", "user", "username", "you", "yourname", "example",
                      "someone", "me", "foo", "bar", "alice", "bob", "test",
                      "server", "host", "acct"}
_SCAN_SUFFIXES = {".py", ".json", ".md", ".toml", ".cfg", ".ini", ".yaml", ".yml"}
_SCAN_SELF = Path(__file__).name

_PAYLOAD = json.dumps({
    "hook_event_name": "PreToolUse",
    "session_id": "PATHDEP",
    "tool_name": "Bash",
    "tool_input": {"command": "rm -rf /tmp/x"},
}, ensure_ascii=False)

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {label}" + (f" -- {detail}" if detail else ""))
    if not ok:
        failures.append(label)


def copy_project(dest: Path) -> Path:
    """Copy the project (minus caches) into `dest` and return the new root."""
    dest.mkdir(parents=True, exist_ok=True)
    for entry in ROOT.iterdir():
        if entry.name in SKIP_DIRS:
            continue
        target = dest / entry.name
        if entry.is_dir():
            shutil.copytree(
                entry, target,
                ignore=shutil.ignore_patterns(*SKIP_DIRS, "*.pyc"),
            )
        else:
            shutil.copy2(entry, target)
    return dest


def _clean_env() -> dict:
    """Environment for a spawned hook.

    QGUARD_AUDIT_DIR is ALWAYS stripped: a value exported in the parent shell
    would otherwise redirect the hook's state and make this probe assert
    against the wrong directory. This actually happened -- a stale value from
    an earlier probe run silently sent state to %TEMP%.
    """
    env = dict(os.environ)
    env.pop("QGUARD_AUDIT_DIR", None)
    env["QGUARD_BLOCK"] = "1"
    return env


def run_hook(project: Path, hook_arg: str, cwd: Path,
             isolate_state: bool = True) -> tuple[int, str, str]:
    """Invoke the hook the way the registered command does.

    `hook_arg` is passed verbatim, so the caller controls the slash style.
    """
    env = _clean_env()
    if isolate_state:
        env["QGUARD_AUDIT_DIR"] = str(project / "_state_from_probe")
    proc = subprocess.run(
        [UV, "run", "--project", str(project), "python", hook_arg],
        input=_PAYLOAD.encode("utf-8"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=str(cwd), timeout=300,
    )
    return (proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


def hook_path(project: Path, style: str) -> str:
    """Render the hook path in a given slash style."""
    native = str(project / HOOK_REL)
    if style == "back":
        return native
    if style == "forward":
        return native.replace("\\", "/")
    # mixed: the drive prefix keeps its backslash, everything after uses forward
    # slashes. This is the form that broke the old bootstrap.
    return native[:3] + native[3:].replace("\\", "/")


def scan_hardcoded_paths() -> list[str]:
    """Return tracked files that hardcode a machine-specific absolute path."""
    hits: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SCAN_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.name == _SCAN_SELF:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            # A capture of only dots is an ellipsis in a documentation example
            # (`\\server\...`), not an account name.
            owners = [o for o in _ABS_PATH_RE.findall(line)
                      if set(o) != {"."}]
            if any(o.lower() not in _PLACEHOLDER_USERS for o in owners):
                hits.append(f"{path.relative_to(ROOT)}:{lineno}")
    return hits


# A user-level config whose hook points at a DIFFERENT copy of the project must
# be reported as a hard failure: the code being edited is not the code running.
# {other} is substituted with str.replace (not str.format -- the JSON braces
# would be read as format fields).
_FAKE_SETTINGS = """{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command",
       "command": "uv run --project \\"{other}\\" python \\"{other}/guard/observe_hook.py\\""}]}
    ]
  }
}
"""


def _fake_settings(other: Path) -> str:
    return _FAKE_SETTINGS.replace("{other}", other.as_posix())


def _run(cmd: list[str], env: dict, cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=str(cwd), timeout=300,
    )
    return proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace")


def check_stale_registration_detected(project: Path) -> None:
    """Both registration checks must agree, in all three states.

    verify_setup.py and install_hooks.py --check look at the same config and
    used to disagree: --check only tested that the script exists, so a
    registration pointing at ANOTHER copy printed OK while verify_setup
    reported a failure. The duplication is deliberate (install_hooks must stay
    runnable when the guard package is broken), so the agreement is asserted
    here instead.

    HOME is redirected to a fake home so the real ~/.qoder-cn/settings.json is
    never read or written.
    """
    fake_home = project / "_fake_home"
    (fake_home / ".qoder-cn").mkdir(parents=True, exist_ok=True)
    settings = fake_home / ".qoder-cn" / "settings.json"

    env = _clean_env()
    env["USERPROFILE"] = str(fake_home)
    env["HOME"] = str(fake_home)

    verify = [UV, "run", "--project", str(project), "python",
              str(project / "guard" / "verify_setup.py"), "--quick"]
    install_check = [UV, "run", "--project", str(project), "python",
                     str(project / "guard" / "install_hooks.py"), "--check"]

    # --- state 1: registration points at the ORIGINAL project ---------------
    settings.write_text(_fake_settings(ROOT), encoding="utf-8")
    code, out = _run(verify, env, project)
    check("verify_setup flags a registration pointing elsewhere",
          "DIFFERENT copy" in out and code != 0, f"exit={code}")
    code2, out2 = _run(install_check, env, project)
    check("install_hooks --check flags the same DIFFERENT copy",
          "DIFFERENT" in out2 and code2 != 0, f"exit={code2}")

    # --- state 2: registration points at a path that does not exist ---------
    settings.write_text(_fake_settings(project.parent / "gone"), encoding="utf-8")
    code, out = _run(verify, env, project)
    check("verify_setup flags a MISSING script",
          "MISSING" in out and code != 0, f"exit={code}")
    code2, out2 = _run(install_check, env, project)
    check("install_hooks --check flags the same MISSING script",
          "MISSING" in out2 and code2 != 0, f"exit={code2}")

    # --- state 3: healthy -- both must pass ---------------------------------
    settings.write_text(_fake_settings(project), encoding="utf-8")
    code, out = _run(verify, env, project)
    check("verify_setup passes when the registration matches",
          code == 0, f"exit={code}")
    code2, out2 = _run(install_check, env, project)
    check("install_hooks --check passes when the registration matches",
          code2 == 0, f"exit={code2}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="qguard_pathdep_"))
    try:
        # --- 1. no machine-specific paths -----------------------------------
        print("1. no machine-specific absolute paths in the repo")
        hits = scan_hardcoded_paths()
        check("no hardcoded absolute paths", not hits,
              f"{len(hits)} hit(s): " + ", ".join(hits[:6]) if hits else "")

        # A deliberately hostile path shape: a space and a non-ASCII character.
        sandbox = tmp / "moved dir \u6d4b\u8bd5" / "qguard copy"
        project = copy_project(sandbox)
        print(f"\ncopy: {project}")

        # --- 2. cwd independence --------------------------------------------
        print("2. cwd independence")
        for label, cwd in [
            ("cwd = project root", project),
            ("cwd = parent dir", project.parent),
            ("cwd = unrelated temp", tmp),
        ]:
            code, out, err = run_hook(project, hook_path(project, "back"), cwd)
            check(label, code == 2, f"exit={code}")

        # --- 3. slash styles ------------------------------------------------
        print("3. slash styles (mixed is the regression case)")
        for style in ("back", "forward", "mixed"):
            code, out, err = run_hook(project, hook_path(project, style), tmp)
            check(f"{style} slashes from unrelated cwd", code == 2, f"exit={code}")

        # --- 4. path shapes -------------------------------------------------
        print("4. hostile path shape (space + non-ASCII)")
        check("copy lives under a space + non-ASCII path",
              " " in str(project) and not str(project).isascii(), str(project))

        # --- 5. state follows the code --------------------------------------
        print("5. state directory follows the script")
        code, out, err = run_hook(project, hook_path(project, "back"), project,
                                  isolate_state=False)
        state_db = project / "audit_logs" / "guard_state.db"
        check("copy wrote its own audit db", state_db.exists(), str(state_db))
        if state_db.exists():
            original_db = ROOT / "audit_logs" / "guard_state.db"
            same = (original_db.exists()
                    and state_db.read_bytes() == original_db.read_bytes())
            check("copy's db is not a copy of the original", not same)

        # --- 6. stale registration is detected ------------------------------
        print("6. a registration pointing at another copy is detected")
        check_stale_registration_detected(project)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        print(f"RESULT: {len(failures)} failure(s): {failures}")
        return 1
    print("RESULT: path independence holds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
