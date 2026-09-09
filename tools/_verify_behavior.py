"""Behavior test for hooks.py decision logic.

Verifies the hook still makes the same allow/deny decisions, that the deny
payload still uses the exact protocol Qoder expects, and that the UNKNOWN
review hand-off works end to end.
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

from qoder_guard import review  # noqa: E402
from qoder_guard.hooks import handle_stdin  # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Isolate review state: the hook writes queue/approval files, and this test
# must not touch the real audit data.
review.AUDIT_DIR = Path(_TMP.name)
review.PENDING_FILE = review.AUDIT_DIR / "pending_review.jsonl"
review.APPROVALS_FILE = review.AUDIT_DIR / "approvals.jsonl"
review.REVIEWS_DIR = review.AUDIT_DIR / "reviews"


def ev(name: str, tool: str, inp: dict) -> str:
    return json.dumps({
        "hook_event_name": name, "session_id": "I18N_TEST", "cwd": str(ROOT),
        "tool_name": tool, "tool_input": inp,
    }, ensure_ascii=False)


CASES = [
    # (label, raw, block_mode, expected_exit)
    ("observe: rm -rf (allow)", ev("PreToolUse", "Bash", {"command": "rm -rf /tmp"}), False, 0),
    ("block:   rm -rf (deny)", ev("PreToolUse", "Bash", {"command": "rm -rf /tmp"}), True, 2),
    ("block:   rmdir  (deny)", ev("PreToolUse", "Bash", {"command": "rmdir /tmp/x"}), True, 2),
    ("block:   ls     (allow)", ev("PreToolUse", "Bash", {"command": "ls -la"}), True, 0),
    ("block:   git push (allow, medium)", ev("PreToolUse", "Bash", {"command": "git push"}), True, 0),
    # Regression: opaque in ARGUMENT position must stay gradeable (was UNKNOWN -> DENY).
    ("block:   echo $HOME (allow, low)", ev("PreToolUse", "Bash", {"command": "echo $HOME"}), True, 0),
    ("block:   rm -rf $DIR (deny, high)", ev("PreToolUse", "Bash", {"command": "rm -rf $DIR"}), True, 2),
    # First sighting of an opaque HEAD is held for review, not silently denied.
    ("block:   opaque head (held for review)", ev("PreToolUse", "Bash", {"command": "x=rm; $x -rf /"}), True, 2),
    ("block:   Write (allow, medium)", ev("PreToolUse", "Write", {"file_path": "a.py", "content": "x"}), True, 0),
    ("block:   SessionStart (non-blockable)", ev("SessionStart", "", {}), True, 0),
    ("garbage JSON (never crash)", "not json at all", True, 0),
    ("empty input (never crash)", "", True, 0),
]

fails = []
for label, raw, block, expected in CASES:
    try:
        got = handle_stdin(raw, block_high_risk=block)
    except Exception as e:
        got = f"RAISED {type(e).__name__}"
    status = "OK  " if got == expected else "FAIL"
    if got != expected:
        fails.append(f"{label}: got {got}, expected {expected}")
    print(f"  [{status}] {label:44} exit={got}")

# -- UNKNOWN hand-off: queue -> approve -> replay --------------------------
print("\n=== UNKNOWN review hand-off ===")
cmd = "x=rm; $x -rf /"
fp = review.fingerprint("Bash", cmd)
queued = [r for r in review.pending() if r["id"] == fp]
if len(queued) == 1:
    print(f"  [OK  ] queued for review, id={fp}")
else:
    fails.append(f"expected 1 queued review for {fp}, got {len(queued)}")
    print(f"  [FAIL] expected 1 queued review, got {len(queued)}")

if review.lookup(fp) is None:
    print("  [OK  ] no decision cached yet")
else:
    fails.append("unexpected cached decision before approval")

review.resolve(fp, review.DECISION_ALLOW, reason="verified safe in test", reviewer="test")
got = handle_stdin(ev("PreToolUse", "Bash", {"command": cmd}), block_high_risk=True)
if got == 0:
    print("  [OK  ] approved command replays as allow (exit=0)")
else:
    fails.append(f"approved command should allow, got exit={got}")
    print(f"  [FAIL] approved command got exit={got}")

# A denied fingerprint keeps blocking
cmd2 = "$y -rf /"
fp2 = review.fingerprint("Bash", cmd2)
handle_stdin(ev("PreToolUse", "Bash", {"command": cmd2}), block_high_risk=True)
review.resolve(fp2, review.DECISION_DENY, reason="too dangerous", reviewer="test")
got = handle_stdin(ev("PreToolUse", "Bash", {"command": cmd2}), block_high_risk=True)
if got == 2:
    print("  [OK  ] denied command stays blocked (exit=2)")
else:
    fails.append(f"denied command should block, got exit={got}")
    print(f"  [FAIL] denied command got exit={got}")

# The deny payload must match the protocol exactly (this is what Qoder parses)
print("\n=== deny payload protocol ===")
import io
from contextlib import redirect_stdout  # noqa: E402

buf = io.StringIO()
with redirect_stdout(buf):
    handle_stdin(ev("PreToolUse", "Bash", {"command": "rm -rf /tmp"}), block_high_risk=True)
payload = buf.getvalue().strip()
try:
    obj = json.loads(payload)
    hso = obj["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse", hso
    assert hso["permissionDecision"] == "deny", hso
    assert isinstance(hso["permissionDecisionReason"], str) and hso["permissionDecisionReason"]
    print("  [OK  ] permissionDecision=deny, hookEventName, reason present")
    print("  reason:", hso["permissionDecisionReason"][:90])
except Exception as e:
    fails.append(f"deny payload malformed: {e}")
    print("  [FAIL]", e, payload[:200])

print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("ALL BEHAVIOR TESTS PASSED")
