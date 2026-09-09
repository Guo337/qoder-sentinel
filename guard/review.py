"""Review CLI: the supervising agent's interface to the UNKNOWN review queue.

Usage:
    python guard/review.py list                 # show pending UNKNOWN calls
    python guard/review.py show <id>            # full detail of one request
    python guard/review.py approve <id> [note]  # allow this command from now on
    python guard/review.py deny <id> [note]     # keep blocking it
    python guard/review.py stats                # pending / approved / denied counts

Workflow
--------
1. A Qoder tool call grades UNKNOWN (e.g. `x=rm; $x -rf /` -- the command name
   itself comes from a variable). The hook denies it once and queues a request.
2. Run `list` to see what is waiting. Each entry shows the exact command text
   and why it could not be graded.
3. Analyse it -- if the command is genuinely safe (say the variable is only ever
   set to `ls`), run `approve <id>`. The decision is cached by fingerprint, so
   every later identical call passes without asking again.
4. If it is dangerous, `deny <id>` records that judgement for the audit trail.

Approvals are keyed by tool + command text, so approving one command never
widens permissions for a different one.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qoder_guard import review  # noqa: E402


def _out(text: str = "") -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(text)


def _cmd_list() -> int:
    items = review.pending()
    if not items:
        _out("No pending reviews.")
        return 0
    _out(f"{len(items)} pending review(s):")
    _out("")
    for rec in items:
        _out(f"  id      : {rec.get('id')}")
        _out(f"  tool    : {rec.get('tool')}")
        _out(f"  command : {rec.get('command')}")
        _out(f"  reason  : {rec.get('reason')}")
        _out(f"  session : {rec.get('session_id')}")
        _out(f"  time    : {rec.get('ts')}")
        _out("  " + "-" * 68)
    _out("Approve with: python guard/review.py approve <id> [note]")
    return 0


def _cmd_show(rid: str) -> int:
    for rec in review.pending():
        if rec.get("id") == rid:
            _out(f"id      : {rec.get('id')}")
            _out(f"tool    : {rec.get('tool')}")
            _out(f"command : {rec.get('command')}")
            _out(f"reason  : {rec.get('reason')}")
            _out(f"session : {rec.get('session_id')}")
            _out(f"time    : {rec.get('ts')}")
            return 0
    decided = review.lookup(rid)
    if decided is not None:
        _out(f"Already decided: {decided.get('decision')} by {decided.get('reviewer')}")
        _out(f"note: {decided.get('reason')}")
        return 0
    _out(f"No review request with id {rid!r}.")
    return 1


def _cmd_resolve(rid: str, decision: str, note: str) -> int:
    try:
        rec = review.resolve(rid, decision, reason=note, reviewer="copilot")
    except ValueError as exc:
        _out(f"Error: {exc}")
        return 1
    _out(f"{rec['decision'].upper()}: {rid}")
    if rec.get("command"):
        _out(f"  command: {rec['command']}")
    if note:
        _out(f"  note   : {note}")
    if decision == review.DECISION_ALLOW:
        _out("  effect : identical future calls will pass without asking")
    return 0


def _cmd_stats() -> int:
    s = review.stats()
    _out(f"pending : {s['pending']}")
    _out(f"approved: {s['approved']}")
    _out(f"denied  : {s['denied']}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        _out(__doc__)
        return 1
    action = argv[1].lower()
    rest = argv[2:]
    if action == "list":
        return _cmd_list()
    if action == "stats":
        return _cmd_stats()
    if action == "show":
        if not rest:
            _out("Usage: python guard/review.py show <id>")
            return 1
        return _cmd_show(rest[0])
    if action in ("approve", "deny"):
        if not rest:
            _out(f"Usage: python guard/review.py {action} <id> [note]")
            return 1
        decision = review.DECISION_ALLOW if action == "approve" else review.DECISION_DENY
        return _cmd_resolve(rest[0], decision, " ".join(rest[1:]))
    _out(f"Unknown action: {action!r}")
    _out(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
