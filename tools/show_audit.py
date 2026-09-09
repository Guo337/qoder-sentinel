"""View the last N entries of the audit log (read-only).

Reads the SQLite state store via the public `audit` API. The legacy JSONL file
is no longer the source of truth; use `audit.export_jsonl()` or
`tools/migrate_audit_to_sqlite.py` if you need JSONL.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from qoder_guard import audit  # noqa: E402

n = int(sys.argv[1]) if len(sys.argv) > 1 else 12
rows = audit.all_records()
print("Total audit entries:", len(rows))
for r in rows[-n:]:
    inp = r.get("tool_input")
    brief = ""
    if isinstance(inp, dict):
        brief = str(inp.get("command") or inp.get("description") or inp)[:60]
    ts = (r.get("ts") or "")[11:19]
    ev = r.get("event", "")
    tool = str(r.get("tool") or "")
    risk = r.get("risk") or "-"
    print(f"{ts} {ev:16} {tool:10} {risk:7} {brief}")
