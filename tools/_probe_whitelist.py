"""Probe: does the read-only whitelist swallow dangerous text in one segment?

`_grade_line` checks `_LOW_RULES` with `.match()` (first word only) BEFORE the
HIGH/MEDIUM rules. So any segment starting with `echo`/`cat`/`grep`/... is LOW
no matter what follows it *inside the same segment*. This probe pins the
current behaviour so a fix can be measured against it.

Read-only: does not touch real guard state.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Isolate audit + review output: set env var before importing qoder_guard modules.
_TMP = tempfile.TemporaryDirectory()
os.environ["QGUARD_AUDIT_DIR"] = _TMP.name

sys.stdout = io.StringIO()


def out(*a):
    print(*a)


from qoder_guard import audit, review  # noqa: E402
from qoder_guard.risk import assess  # noqa: E402

review.AUDIT_DIR = Path(_TMP.name)
review.PENDING_FILE = review.AUDIT_DIR / "pending_review.jsonl"
review.APPROVALS_FILE = review.AUDIT_DIR / "approvals.jsonl"
review.REVIEWS_DIR = review.AUDIT_DIR / "reviews"


def grade(cmd: str) -> str:
    return assess("Bash", {"command": cmd})[0].value


# (command, expected_after_fix, why it matters)
CASES = [
    # -- whitelist head + redirect: a write disguised as read-only --
    ("echo hi > out.txt",        "medium", "writes a file via redirect"),
    ("echo hi >> log.txt",       "medium", "appends to a file"),
    ("cat a > b",                "medium", "copies file content via redirect"),
    ("echo secret > /etc/passwd", "medium", "overwrites a system file"),
    ("echo x > ~/.ssh/authorized_keys", "medium", "overwrites an auth file"),
    # -- whitelist head, no redirect: must stay LOW --
    ("echo hello",               "low",    "plain echo"),
    ("echo $HOME",               "low",    "echo with a runtime argument"),
    ("ls -la",                   "low",    "plain ls"),
    ("grep rm -rf notes.txt",    "low",    "rm is an ARGUMENT, not a command"),
    ("cat README.md",            "low",    "plain cat"),
    ("git status",               "low",    "read-only git"),
    # -- comparison must not be mistaken for a redirect --
    ("test 3 -gt 2",             "low",    "comparison operator"),
    ("[ 1 -gt 0 ]",              "low",    "bracket test"),
    # -- real danger behind a whitelist head in the SAME segment --
    ("echo hi && rm -rf /tmp",   "high",   "separator splits; already handled"),
    ("ls; rm -rf /tmp",          "high",   "separator splits; already handled"),
    # A command substitution body is graded directly (better than UNKNOWN: the
    # guard can name the rule that matched) -- see risk._grade_substitutions.
    ("echo $(rm -rf /tmp)",      "high",   "command substitution body is graded"),
    ("cat `rm -rf /tmp`",        "high",   "backtick substitution body is graded"),
    ("echo $(whoami)",           "low",    "harmless substitution stays low"),
    ("echo hi > out2.txt",       "medium", "redirect without surrounding spaces"),
    ("echo hi>out3.txt",         "medium", "redirect with no space at all"),
    ("rmdir /tmp/x 2>&1",        "high",   "fd redirect must not be read as a write"),
]

print("=== whitelist vs dangerous suffix ===")
rows = []
for cmd, want, why in CASES:
    got = grade(cmd)
    ok = got == want
    rows.append((ok, cmd, got, want, why))
    print(f"  [{'OK ' if ok else 'BAD'}] {got:8} want {want:8} | {cmd}")

bad = sum(1 for r in rows if not r[0])
print(f"  -> {bad} mismatch(es)")

print()
print("=== detail for the mismatching ones ===")
for ok, cmd, got, want, why in rows:
    if not ok:
        lvl, reason = assess("Bash", {"command": cmd})
        print(f"  {cmd!r}")
        print(f"    got={got} want={want}  ({why})")
        print(f"    reason={reason}")

pathlib.Path("tools/_probe_whitelist_out.json").write_text(
    json.dumps(
        [{"cmd": c, "got": g, "want": w, "ok": o, "why": y} for o, c, g, w, y in rows],
        ensure_ascii=False, indent=2,
    ),
    encoding="utf-8",
)
text = sys.stdout.getvalue()
sys.stdout = sys.__stdout__
pathlib.Path("tools/_probe_whitelist_out.txt").write_text(text, encoding="utf-8")
print(f"probe done: {bad} mismatch(es); see tools/_probe_whitelist_out.txt")
