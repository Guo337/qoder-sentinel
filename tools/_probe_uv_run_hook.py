"""Probe: hook stdout must stay clean when launched through `uv run`.

Read-only. Exit 0 only if the hook still emits exactly one JSON line.

Why this exists (2026-09-08): the hook command is registered in Qoder's config
as an absolute interpreter + script. To make the tree-sitter dependency
survive `rm -rf .venv`, the command becomes `uv run --project <root> python
<script>`. That inserts uv between Qoder and the hook, and uv is free to print
progress to stderr -- but if it ever prints to STDOUT the hook's JSON contract
breaks and Qoder silently stops enforcing decisions.

So this probe spawns the REAL entry point both ways and compares the two
stdout streams byte for byte.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "guard" / "observe_hook.py"

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_ISOLATED = tempfile.TemporaryDirectory(prefix="qguard_uvrun_")
ISOLATED_DIR = _ISOLATED.name


def _env() -> dict:
    env = dict(os.environ)
    env["QGUARD_AUDIT_DIR"] = ISOLATED_DIR
    env["QGUARD_BLOCK"] = "1"
    env["PYTHONIOENCODING"] = ""
    return env


def _payload(command: str) -> str:
    return json.dumps({
        "hook_event_name": "PreToolUse",
        "session_id": "UVRUN",
        "cwd": str(ROOT),
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }, ensure_ascii=False)


def _run_direct(command: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=_payload(command).encode("utf-8"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=_env(), cwd=str(ROOT), timeout=120,
    )
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


def _run_via_uv(command: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["uv", "run", "--project", str(ROOT), "python", str(HOOK)],
        input=_payload(command).encode("utf-8"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=_env(), cwd=str(ROOT), timeout=180,
    )
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


# (command, expected exit code, description)
CASES: list[tuple[str, int, str]] = [
    ("ls -la", 0, "read-only passes"),
    ("rm -rf /tmp", 2, "high risk blocked"),
    ("(rm -rf /)", 2, "structural escape must be blocked"),
    ("echo hi", 0, "benign command passes"),
]


def main() -> int:
    failures: list[str] = []

    if not HOOK.exists():
        print(f"FAIL hook not found: {HOOK}")
        return 1

    try:
        subprocess.run(["uv", "--version"], capture_output=True, timeout=60, check=True)
    except Exception as exc:
        print(f"SKIP uv not available: {exc}")
        return 0

    print(f"{'command':20} {'direct':18} {'via uv':18} note")
    print("-" * 96)
    for command, expected, note in CASES:
        d_code, d_out, d_err = _run_direct(command)
        u_code, u_out, u_err = _run_via_uv(command)

        ok = True
        if d_code != expected:
            failures.append(f"direct {command!r}: exit {d_code} != {expected} ({d_err.strip()[:120]})")
            ok = False
        if u_code != expected:
            failures.append(f"uv {command!r}: exit {u_code} != {expected} ({u_err.strip()[:120]})")
            ok = False
        if d_out != u_out:
            failures.append(
                f"stdout differs for {command!r}: direct={d_out[:80]!r} uv={u_out[:80]!r}"
            )
            ok = False
        if u_out.count("\n") > 1:
            failures.append(f"uv stdout has extra lines for {command!r}: {u_out[:200]!r}")
            ok = False
        if u_out.strip():
            try:
                json.loads(u_out.strip().splitlines()[0])
            except Exception as exc:
                failures.append(f"uv stdout is not valid JSON for {command!r}: {exc}")
                ok = False

        print(f"{command:20} exit={d_code} {len(d_out):5}b   exit={u_code} {len(u_out):5}b   "
              f"{'ok' if ok else 'FAIL'}  {note}")

    print()
    print(f"failures={len(failures)}")
    for failure in failures:
        print(f"  FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
