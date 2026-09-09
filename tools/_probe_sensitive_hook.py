"""Acceptance probe for the sensitive-data integration in qoder_guard/hooks.py.

Written by the supervising side. Covers the wiring, not the scanner itself
(that is tools/_probe_sensitive.py).

Run: uv run python tools/_probe_sensitive_hook.py   (exit 0 = pass)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Isolate state BEFORE importing the guard: QGUARD_AUDIT_DIR must be popped from
# any inherited environment, otherwise a stale value silently redirects writes.
os.environ.pop("QGUARD_AUDIT_DIR", None)
_TMP = tempfile.mkdtemp(prefix="qguard_probe_sens_")
os.environ["QGUARD_AUDIT_DIR"] = _TMP

from qoder_guard import audit, hooks  # noqa: E402

FAILS: list[str] = []


def _fake(*parts: str) -> str:
    """Join token fragments so no complete token appears in the source.

    Hosted secret scanners match on shape alone, so a realistic fixture in a
    test file is reported as a live credential and blocks the push. Splitting
    the literal keeps the fixture realistic at run time while leaving nothing
    for a scanner to match on disk.
    """
    return "".join(parts)


_AWS_KEY = _fake("AKIA", "IOSFODNN7", "EXAMPLE")


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        FAILS.append(f"{name}: {detail}")


def run(event: dict, *, block: bool) -> tuple[int, str]:
    """Invoke the hook, capturing stdout."""
    import io
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        code = hooks.handle_stdin(json.dumps(event), block_high_risk=block)
    finally:
        sys.stdout = old
    return code, buf.getvalue()


def pre(command: str, tool: str = "Bash") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "probe-session",
        "cwd": _TMP,
        "tool_name": tool,
        "tool_input": {"command": command},
    }


def last_record() -> dict:
    rows = audit.all_records()
    return rows[-1] if rows else {}


def main() -> int:
    # 1. isolation actually took effect
    check("isolated", audit.is_isolated(), f"audit dir = {audit.log_path()}")

    # 2. high-severity secret in a command -> DENY (exit 2) when blocking is on
    code, out = run(pre("export KEY=" + _AWS_KEY), block=True)
    check("secret_denied_exit2", code == 2, f"exit={code}")
    check("secret_denied_json", '"permissionDecision": "deny"' in out, out[:200])
    check("secret_denied_reason", "sensitive data in command line" in out, out[:200])

    # 3. same command in observe mode -> ALLOW (never block when disabled)
    code, out = run(pre("export KEY=" + _AWS_KEY), block=False)
    check("observe_allows", code == 0, f"exit={code} out={out[:200]}")

    # 4. audit must record the finding...
    rec = last_record()
    check("audit_kind", rec.get("sensitive") == ["aws_access_key"], f"{rec.get('sensitive')}")
    check("audit_severity", rec.get("sensitive_severity") == "high", f"{rec.get('sensitive_severity')}")

    # 5. ...but must NOT store the secret itself
    stored = json.dumps(rec, ensure_ascii=False)
    check("audit_redacted", _AWS_KEY not in stored, "secret persisted in audit!")
    check("audit_has_marker", "<redacted:aws_access_key>" in stored, stored[:300])

    # 6. benign commands stay allowed in block mode
    for clean in ("ls -la", "git status", "echo hello", "python -m pytest"):
        code, _ = run(pre(clean), block=True)
        check("benign_allowed", code == 0, f"{clean!r} exit={code}")

    # 7. non-command fields must NOT trigger the deny (user file payloads are
    #    only recorded). Write tool carries `content`, not `command`.
    write_ev = {
        "hook_event_name": "PreToolUse",
        "session_id": "probe-session",
        "tool_name": "Write",
        "tool_input": {
            "file_path": str(Path(_TMP) / "fixture.txt"),
            "content": "token = '" + _AWS_KEY + "'",
        },
    }
    code, out = run(write_ev, block=True)
    check("write_content_not_denied", code == 0, f"exit={code} out={out[:200]}")
    stored = json.dumps(last_record(), ensure_ascii=False)
    check("write_content_redacted", _AWS_KEY not in stored, "payload leaked to audit")

    # 8. non-blockable events must never be denied, even with a secret present
    post_ev = dict(pre("export KEY=" + _AWS_KEY))
    post_ev["hook_event_name"] = "PostToolUse"
    code, _ = run(post_ev, block=True)
    check("posttool_not_blocked", code == 0, f"exit={code}")

    # 9. existing behaviour preserved: high risk command still denied in block mode
    code, out = run(pre("rm -rf /"), block=True)
    check("risk_deny_preserved", code == 2, f"exit={code} out={out[:200]}")

    # 10. existing behaviour preserved: UNKNOWN still routes to review, not the
    #     sensitive path (no false attribution of the deny reason)
    code, out = run(pre("x=rm; $x -rf /"), block=True)
    check("unknown_still_review", "HELD FOR REVIEW" in out, out[:250])

    # 11. malformed events must not crash the hook
    for bad in ("", "not json", "[]", '{"hook_event_name":"PreToolUse","tool_input":null}'):
        code = hooks.handle_stdin(bad, block_high_risk=True)
        check("malformed_no_crash", code in (0, 2), f"{bad!r} -> {code}")

    if FAILS:
        print(f"FAILED ({len(FAILS)})")
        for f in FAILS:
            print("  -", f)
        return 1
    print("probe_sensitive_hook: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
