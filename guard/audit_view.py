"""Audit panel (minimal CLI version, stage A).

Fills the gap in Qoder's "execution audit panel": independent of conversation
logs, summarizes the timeline, risk distribution, and raw commands for every
tool call Qoder makes.

Usage (from project root):
  python guard/audit_view.py            # show last 20 entries
  python guard/audit_view.py --session <id>   # filter by session
  python guard/audit_view.py --risk high      # high risk only
  python guard/audit_view.py --json          # raw JSON output
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qoder_guard import audit  # noqa: E402

RISK_ICON = {"low": "🟢", "medium": "🟡", "high": "🔴", None: "⚪"}


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    args = sys.argv[1:]
    filter_session = None
    filter_risk = None
    as_json = False
    limit = 20

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--session" and i + 1 < len(args):
            filter_session = args[i + 1]
            i += 1
        elif a == "--risk" and i + 1 < len(args):
            filter_risk = args[i + 1]
            i += 1
        elif a == "--json":
            as_json = True
        elif a == "-n" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 1
        i += 1

    # Records come from the SQLite state store, oldest first.
    records = audit.all_records()
    if not records:
        print("Audit log is empty; no tasks have been run yet.")
        return 0

    if filter_session:
        records = [r for r in records if r.get("session_id") == filter_session]
    if filter_risk:
        records = [r for r in records if r.get("risk") == filter_risk]

    if as_json:
        print(json.dumps(records[-limit:], ensure_ascii=False, indent=2))
        return 0

    if not records:
        print("No matching records.")
        return 0

    # Summary statistics
    from collections import Counter
    events = Counter(r.get("event") for r in records)
    risks = Counter(r.get("risk") for r in records if r.get("risk"))

    print("=== Qoder Execution Audit ===")
    print(f"Total events: {len(records)}"
          f" | Event distribution: {dict(events)}"
          f" | Risk distribution: {dict(risks)}")
    print("─" * 72)

    # Timeline: group tool calls by session
    for r in records[-limit:]:
        ev = r.get("event")
        if ev not in ("PreToolUse", "PostToolUse"):
            continue  # Pre/Post tool use are the audit focus
        tool = r.get("tool") or "(?)"
        risk = r.get("risk")
        icon = RISK_ICON.get(risk, "⚪")
        ts = (r.get("ts") or "")[11:19]
        inp = r.get("tool_input")
        brief = ""
        if isinstance(inp, dict):
            # For command tools take command; for file tools take path
            brief = inp.get("command") or inp.get("file_path") or json.dumps(inp, ensure_ascii=False)
        elif isinstance(inp, str):
            brief = inp
        brief = (brief or "")[:100].replace("\n", " ")
        marker = "PENDING" if ev == "PreToolUse" else "DONE"
        print(f"{ts} {icon} [{marker}] {tool}")
        if brief:
            print(f"      {brief}")
        if r.get("risk_reason"):
            print(f"      Reason: {r['risk_reason']}")

    print("─" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
