"""End-to-end hook simulation: spawn observe_hook.py exactly as Qoder does.

This is the only test that exercises the REAL entry point (stdin encoding
reconfiguration, env var, exit codes, stdout JSON) instead of importing
handle_stdin in-process.

Every hook invocation runs with QGUARD_AUDIT_DIR pointed at a temporary
directory, so the production state database is never touched by a test.

Run:  python tools/_e2e_hook.py
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable
HOOK = ROOT / "guard" / "observe_hook.py"

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Isolated state directory for every hook spawned below.
_ISOLATED = tempfile.TemporaryDirectory(prefix="qguard_e2e_")
ISOLATED_DIR = _ISOLATED.name


def _base_env() -> dict:
    env = dict(os.environ)
    env["QGUARD_AUDIT_DIR"] = ISOLATED_DIR
    env["PYTHONIOENCODING"] = ""  # let the hook reconfigure the streams itself
    return env


def run_hook(payload: str, *, block: bool, cwd: pathlib.Path | None = None):
    env = _base_env()
    env["QGUARD_BLOCK"] = "1" if block else ""
    proc = subprocess.run(
        [PY, str(HOOK)],
        input=payload.encode("utf-8"),   # Qoder sends UTF-8
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=str(cwd or ROOT), timeout=60,
    )
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def event(name, tool, inp, session="E2E"):
    return json.dumps({
        "hook_event_name": name, "session_id": session, "cwd": str(ROOT),
        "tool_name": tool, "tool_input": inp,
    }, ensure_ascii=False)


CASES = [
    ("observe high",      event("PreToolUse", "Bash", {"command": "rm -rf /tmp"}), False, 0),
    ("block high",        event("PreToolUse", "Bash", {"command": "rm -rf /tmp"}), True, 2),
    ("block read-only",   event("PreToolUse", "Bash", {"command": "ls -la"}), True, 0),
    ("block medium",      event("PreToolUse", "Bash", {"command": "git push"}), True, 0),
    ("block opaque arg",  event("PreToolUse", "Bash", {"command": "echo $HOME"}), True, 0),
    ("block opaque head", event("PreToolUse", "Bash", {"command": "x=rm; $x -rf /"}), True, 2),
    ("CJK Write content", event("PreToolUse", "Write",
                                {"file_path": "a.py", "content": "print('中文测试')"}), True, 0),
    ("CJK in command",    event("PreToolUse", "Bash", {"command": "echo 中文测试"}), True, 0),
    ("post tool use",     event("PostToolUse", "Bash", {"command": "rm -rf /tmp"}), True, 0),
    ("session start",     event("SessionStart", "", {}), True, 0),
    ("bad json",          "not json", True, 0),
    ("empty",             "", True, 0),
]

fails = []
print("=== e2e: real observe_hook.py process ===")
for label, payload, block, expected in CASES:
    code, out, err = run_hook(payload, block=block)
    ok = code == expected
    if not ok:
        fails.append(f"{label}: exit {code}, expected {expected}")
    print(f"  [{'OK ' if ok else 'BAD'}] {label:18} exit={code}")
    if code == 2:
        try:
            obj = json.loads(out.strip().splitlines()[0])
            hso = obj["hookSpecificOutput"]
            assert hso["permissionDecision"] == "deny"
            assert hso["hookEventName"]
            assert hso["permissionDecisionReason"]
        except Exception as exc:
            fails.append(f"{label}: deny payload invalid: {exc}")
            print(f"        payload problem: {exc}")
    if "Traceback" in err:
        fails.append(f"{label}: hook raised an unhandled exception")
        print(f"        {err.strip().splitlines()[-1][:110]}")

print()
print("=== e2e: deny payload is valid JSON on the first stdout line ===")
code, out, err = run_hook(event("PreToolUse", "Bash", {"command": "rm -rf /tmp"}), block=True)
first = out.strip().splitlines()[0] if out.strip() else ""
try:
    obj = json.loads(first)
    print(f"  [OK ] parsed: {json.dumps(obj, ensure_ascii=False)[:110]}")
except Exception as exc:
    fails.append(f"deny stdout not parseable JSON: {exc}")
    print(f"  [BAD] {exc} | raw={first[:120]!r}")

print()
print("=== e2e: hook must never crash on a hostile payload ===")
HOSTILE = [
    "\x00\x01\x02",
    "{}",
    '{"hook_event_name": null}',
    '{"hook_event_name": "PreToolUse", "tool_input": null}',
    '{"hook_event_name": "PreToolUse", "tool_input": [1,2,3]}',
    '{"hook_event_name": "PreToolUse", "tool_input": {"command": 12345}}',
    '{"hook_event_name": "PreToolUse", "tool_input": {"command": "a" * 100000}}',
    # Raw bytes: an invalid UTF-8 sequence must not crash the hook either.
]
RAW_HOSTILE = [b'\xff\xfe\x00', b'{"hook_event_name": "\xff\xfe"}']


def run_hook_bytes(payload: bytes, *, block: bool):
    env = _base_env()
    env["QGUARD_BLOCK"] = "1" if block else ""
    proc = subprocess.run(
        [PY, str(HOOK)], input=payload,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=str(ROOT), timeout=60,
    )
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


for i, payload in enumerate(HOSTILE):
    code, out, err = run_hook(payload, block=True)
    ok = code in (0, 2) and "Traceback" not in err
    if not ok:
        fails.append(f"hostile[{i}] crashed: exit={code} {err.strip()[-120:]}")
    print(f"  [{'OK ' if ok else 'BAD'}] hostile[{i}] exit={code}")

for i, raw in enumerate(RAW_HOSTILE):
    code, out, err = run_hook_bytes(raw, block=True)
    ok = code in (0, 2) and "Traceback" not in err
    if not ok:
        fails.append(f"raw_hostile[{i}] crashed: exit={code} {err.strip()[-120:]}")
    print(f"  [{'OK ' if ok else 'BAD'}] raw_hostile[{i}] exit={code}")

print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("ALL E2E TESTS PASSED")
