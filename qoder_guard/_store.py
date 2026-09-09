"""Guard state store, backed by the standard library `sqlite3`.

Why SQLite instead of hand-rolled files
--------------------------------------
This module replaces two custom implementations that both lost data under
concurrent processes:

  * `audit.py` appended JSONL with `open(path, "a")`  -> lost 21-35% of records
  * `review.py` kept approvals in a read-modify-write JSON object -> lost 75%

The custom fix was `_filelock.py` (131 lines: sidecar lock file + msvcrt
locking). Measured with `tools/_probe_sqlite.py`, SQLite needs none of that:

    mode       procs  expected    rows  distinct  errors
    implicit       4       400     400       400       0
    implicit       8       800     800       800       0
    implicit      16       800     800       800       0
    immediate      4       400     400       400       0
    immediate      8       800     800       800       0
    immediate     16       800     800       800       0

SQLite is part of the Python standard library, so the "zero third-party
dependency" rule for the hook is preserved. The hook runs as a separate process
per tool call, which is exactly the workload SQLite is designed for: multiple
processes, one file, WAL journal, busy_timeout retry.

Schema notes
------------
`audit` keeps the raw record as JSON text. Audit records are heterogeneous
(different events carry different fields), so a fixed column set would either
be sparse or lose data. Queries that need a field use SQLite's JSON functions.

`approvals` is keyed by fingerprint id, so "last decision wins" is just an
UPSERT -- no replay scan, no partial-line handling.

`review_requests` keeps the queue; `status` is 'pending' or 'decided'.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

# State directory resolution lives here (the lowest layer) so that `audit` and
# `review` can both depend on `_store` without a circular import.
AUDIT_DIR_ENV = "QGUARD_AUDIT_DIR"
DB_NAME = "guard_state.db"


def resolve_dir() -> Path:
    """Return the state directory, honouring the QGUARD_AUDIT_DIR override.

    Re-read on every call so a test may set the env var after import.
    """
    override = os.environ.get(AUDIT_DIR_ENV)
    if override:
        return Path(override)
    # Project root = two levels up from this file (qoder_guard/ -> project root)
    return Path(__file__).resolve().parent.parent / "audit_logs"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    record TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);

CREATE TABLE IF NOT EXISTS review_requests (
    id         TEXT PRIMARY KEY,
    ts         TEXT NOT NULL,
    tool       TEXT,
    command    TEXT,
    reason     TEXT,
    session_id TEXT,
    status     TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS approvals (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    decision        TEXT NOT NULL,
    reason          TEXT,
    reviewer        TEXT,
    tool            TEXT,
    command         TEXT,
    original_reason TEXT
);
"""


def db_path() -> Path:
    """Location of the state database (honours QGUARD_AUDIT_DIR)."""
    d = resolve_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / DB_NAME


def _enable_wal(con: sqlite3.Connection, attempts: int = 20) -> None:
    """Switch the database to WAL mode, tolerating a concurrent switch.

    `PRAGMA journal_mode=WAL` is a one-time, exclusive operation and -- unlike
    ordinary statements -- it does NOT honour `busy_timeout`: if another process
    is mid-switch it raises "database is locked" immediately. When several hooks
    start against a brand-new database at the same moment, every loser of that
    race would otherwise fail (measured: 25% of decisions lost at 4 processes).

    So: read the current mode first, and only retry the switch while it is still
    not WAL. Once one process has switched, the others see 'wal' and return.
    """
    try:
        if con.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal":
            return
    except sqlite3.OperationalError:
        pass
    for _ in range(attempts):
        try:
            if con.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal":
                return
        except sqlite3.OperationalError:
            pass
        time.sleep(0.05)


def connect() -> sqlite3.Connection:
    """Open a connection tuned for many short-lived writer processes.

    - WAL lets readers work while a writer holds the write lock.
    - busy_timeout makes a blocked writer wait instead of raising immediately
      (the hook must never fail because a peer is mid-write).
    - synchronous=NORMAL is the standard WAL pairing: durable against process
      crashes, which is what matters here.
    """
    con = sqlite3.connect(db_path(), timeout=30.0, isolation_level=None)
    con.execute("PRAGMA busy_timeout=30000")
    con.execute("PRAGMA synchronous=NORMAL")
    _enable_wal(con)
    con.executescript(_SCHEMA)
    return con


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# -- Audit ------------------------------------------------------------------

def append_audit(record: dict) -> None:
    """Append one audit record (atomic across processes)."""
    if "ts" not in record:
        record["ts"] = _now()
    line = json.dumps(record, ensure_ascii=False, default=str)
    con = connect()
    try:
        con.execute("INSERT INTO audit(ts, record) VALUES (?, ?)", (record["ts"], line))
    finally:
        con.close()


def recent_audit(n: int = 30) -> list[dict]:
    """Last n audit records, oldest first (same shape as the old tail())."""
    con = connect()
    try:
        rows = con.execute(
            "SELECT record FROM audit ORDER BY seq DESC LIMIT ?", (n,)
        ).fetchall()
    finally:
        con.close()
    return [json.loads(r[0]) for r in reversed(rows)]


def count_audit() -> int:
    con = connect()
    try:
        return con.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    finally:
        con.close()


def all_audit() -> list[dict]:
    """Every audit record, oldest first.

    Used by the audit panel, which needs full-history aggregates (event and risk
    distributions). The old JSONL reader also loaded the whole file, so memory
    behaviour is unchanged; if the log ever grows past a few hundred thousand
    rows the panel should switch to SQL aggregates.
    """
    con = connect()
    try:
        rows = con.execute("SELECT record FROM audit ORDER BY seq").fetchall()
    finally:
        con.close()
    return [json.loads(r[0]) for r in rows]


def clear_audit() -> None:
    con = connect()
    try:
        con.execute("DELETE FROM audit")
    finally:
        con.close()


def export_jsonl(path: Path) -> int:
    """Write the audit table out as JSONL (for external tools / archives)."""
    con = connect()
    try:
        rows = con.execute("SELECT record FROM audit ORDER BY seq").fetchall()
    finally:
        con.close()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for (rec,) in rows:
            f.write(rec + "\n")
    return len(rows)


# -- Review queue -----------------------------------------------------------

def enqueue_request(rec: dict) -> None:
    """Insert a review request; re-queueing an existing id refreshes it."""
    con = connect()
    try:
        con.execute(
            "INSERT INTO review_requests(id, ts, tool, command, reason, session_id, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 'pending') "
            "ON CONFLICT(id) DO UPDATE SET ts=excluded.ts, reason=excluded.reason, "
            "status='pending'",
            (rec["id"], rec.get("ts") or _now(), rec.get("tool"), rec.get("command"),
             rec.get("reason"), rec.get("session_id")),
        )
    finally:
        con.close()


def pending_requests() -> list[dict]:
    """Requests still awaiting a decision, newest first."""
    con = connect()
    try:
        rows = con.execute(
            "SELECT id, ts, tool, command, reason, session_id, status "
            "FROM review_requests WHERE status='pending' ORDER BY ts DESC"
        ).fetchall()
    finally:
        con.close()
    keys = ("id", "ts", "tool", "command", "reason", "session_id", "status")
    return [dict(zip(keys, r)) for r in rows]


def request_by_id(rid: str) -> dict | None:
    con = connect()
    try:
        row = con.execute(
            "SELECT id, ts, tool, command, reason, session_id, status "
            "FROM review_requests WHERE id=?", (rid,)
        ).fetchone()
    finally:
        con.close()
    if row is None:
        return None
    keys = ("id", "ts", "tool", "command", "reason", "session_id", "status")
    return dict(zip(keys, row))


def record_decision(rec: dict) -> None:
    """Store a decision (last one for an id wins) and close the request."""
    con = connect()
    try:
        con.execute(
            "INSERT INTO approvals(id, ts, decision, reason, reviewer, tool, command, original_reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET ts=excluded.ts, decision=excluded.decision, "
            "reason=excluded.reason, reviewer=excluded.reviewer",
            (rec["id"], rec.get("ts") or _now(), rec["decision"], rec.get("reason"),
             rec.get("reviewer"), rec.get("tool"), rec.get("command"),
             rec.get("original_reason")),
        )
        con.execute("UPDATE review_requests SET status='decided' WHERE id=?", (rec["id"],))
    finally:
        con.close()


def get_decision(rid: str) -> dict | None:
    con = connect()
    try:
        row = con.execute(
            "SELECT id, ts, decision, reason, reviewer, tool, command, original_reason "
            "FROM approvals WHERE id=?", (rid,)
        ).fetchone()
    finally:
        con.close()
    if row is None:
        return None
    keys = ("id", "ts", "decision", "reason", "reviewer", "tool", "command", "original_reason")
    return dict(zip(keys, row))


def stats() -> dict:
    con = connect()
    try:
        pending = con.execute(
            "SELECT COUNT(*) FROM review_requests WHERE status='pending'"
        ).fetchone()[0]
        approved = con.execute(
            "SELECT COUNT(*) FROM approvals WHERE decision='allow'"
        ).fetchone()[0]
        denied = con.execute(
            "SELECT COUNT(*) FROM approvals WHERE decision='deny'"
        ).fetchone()[0]
    finally:
        con.close()
    return {"pending": pending, "approved": approved, "denied": denied}


# -- Self-test -------------------------------------------------------------
if __name__ == "__main__":
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        os.environ["QGUARD_AUDIT_DIR"] = td

        append_audit({"event": "PreToolUse", "tool": "Bash", "n": 1})
        append_audit({"event": "PostToolUse", "tool": "Bash", "n": 2})
        assert count_audit() == 2
        tail = recent_audit(10)
        assert [r["n"] for r in tail] == [1, 2], tail

        out = Path(td) / "export.jsonl"
        assert export_jsonl(out) == 2
        assert len(out.read_text(encoding="utf-8").strip().splitlines()) == 2

        enqueue_request({"id": "abc", "ts": _now(), "tool": "Bash",
                         "command": "x=rm; $x -rf /", "reason": "opaque head",
                         "session_id": "s1"})
        assert [r["id"] for r in pending_requests()] == ["abc"]
        assert request_by_id("abc")["command"] == "x=rm; $x -rf /"

        record_decision({"id": "abc", "ts": _now(), "decision": "allow",
                         "reason": "checked", "reviewer": "copilot",
                         "tool": "Bash", "command": "x=rm; $x -rf /",
                         "original_reason": "opaque head"})
        assert pending_requests() == []
        assert get_decision("abc")["decision"] == "allow"
        assert stats() == {"pending": 0, "approved": 1, "denied": 0}

        # Last decision wins (UPSERT), and stats follow it.
        record_decision({"id": "abc", "ts": _now(), "decision": "deny",
                         "reason": "reconsidered", "reviewer": "copilot",
                         "tool": "Bash", "command": "x=rm; $x -rf /",
                         "original_reason": "opaque head"})
        assert get_decision("abc")["decision"] == "deny"
        assert stats() == {"pending": 0, "approved": 0, "denied": 1}

        # Re-queueing a decided id must bring it back to pending.
        enqueue_request({"id": "abc", "ts": _now(), "tool": "Bash",
                         "command": "x=rm; $x -rf /", "reason": "again",
                         "session_id": "s2"})
        assert [r["id"] for r in pending_requests()] == ["abc"]
        assert stats()["pending"] == 1

        clear_audit()
        assert count_audit() == 0

    print("_store: all assertions passed")
