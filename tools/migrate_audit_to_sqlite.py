"""One-shot migration: import the legacy JSONL audit log into SQLite.

Why this exists
---------------
`qoder_guard/audit.py` used to append records to
`audit_logs/qoder_audit.jsonl` with a plain `open(path, "a")` write, which lost
21-35% of records when several Qoder processes wrote at once (see
`tools/_probe_concurrency.py`). The audit layer now writes to
`audit_logs/guard_state.db` instead.

The JSONL file itself is *not* deleted: it stays as an immutable archive and as
the source for this import. The script is idempotent by refusing to run when the
database already holds records, so an accidental second run cannot duplicate
history.

Usage (from the project root):
    python tools/migrate_audit_to_sqlite.py            # migrate, then verify
    python tools/migrate_audit_to_sqlite.py --dry-run   # count only, no writes
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qoder_guard import _store  # noqa: E402
from qoder_guard.audit import AUDIT_FILE  # noqa: E402


def _read_jsonl(path: Path) -> tuple[list[dict], int]:
    """Return (valid records, malformed line count)."""
    records: list[dict] = []
    bad = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                bad += 1
                continue
            if isinstance(rec, dict):
                records.append(rec)
            else:
                bad += 1
    return records, bad


def main(argv: list[str]) -> int:
    dry_run = "--dry-run" in argv

    if not AUDIT_FILE.exists():
        print(f"nothing to do: {AUDIT_FILE} does not exist")
        return 0

    records, bad = _read_jsonl(AUDIT_FILE)
    print(f"legacy file : {AUDIT_FILE}")
    print(f"valid lines : {len(records)}")
    print(f"malformed   : {bad}")

    existing = _store.count_audit()
    print(f"db before   : {existing} record(s) in {_store.db_path()}")

    if dry_run:
        print("dry run: no changes written")
        return 0

    if existing:
        print("abort: the database already holds records; refusing to duplicate history.")
        print("       (to re-import, move the database aside first)")
        return 1

    for rec in records:
        _store.append_audit(rec)

    after = _store.count_audit()
    print(f"db after    : {after} record(s)")
    if after != len(records):
        print("MISMATCH: imported count differs from parsed count")
        return 1

    # Round-trip check: export back to JSONL and compare line counts.
    out = AUDIT_FILE.with_name("qoder_audit.exported.jsonl")
    exported = _store.export_jsonl(out)
    print(f"round-trip  : exported {exported} record(s) to {out.name}")
    if exported != after:
        print("MISMATCH: export count differs from database count")
        return 1

    print("migration complete; the legacy JSONL was left untouched as an archive")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
