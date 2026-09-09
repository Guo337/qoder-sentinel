"""Review queue: route statically-undecidable (UNKNOWN) tool calls back to the
supervising agent for analysis and explicit approval.

Why a queue instead of blocking?
--------------------------------
The hook runs as a short-lived subprocess of the Qoder CLI. It cannot talk to
the supervising agent (Copilot) directly, and it must never stall the task by
waiting for a human. So the hand-off goes through shared state:

    UNKNOWN detected
        -> look up the fingerprint in the approvals table
             - approved earlier -> ALLOW
             - not approved     -> queue the request and DENY, with a reason
                                   that names the review id

The supervising agent then runs `guard/review.py list`, reads the command in
context, and calls `guard/review.py approve <id>`. The next identical call is
allowed because the approval is keyed by a command fingerprint -- so a decision
made once is not asked for twice.

Storage
-------
State lives in `guard_state.db` (SQLite, stdlib) under the audit directory.
This replaced two hand-rolled file schemes that both lost data under concurrent
processes: the read-modify-write approvals JSON lost 75% of decisions at 4
processes, and the JSONL rewrite of it still lost records until every append was
serialized by `_filelock`. SQLite needs neither -- see `_store.py` for the
measured comparison. The module keeps its public API so callers are unaffected.

The former files (`pending_review.jsonl`, `approvals.jsonl`, `reviews/<id>.json`)
are migrated into the database once, on first use -- see `migrate_legacy_files`.

Design constraints: zero third-party dependencies (the hook runs on the global
interpreter), English-only source text, and every operation must degrade
gracefully rather than raise into the hook.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

# Reuse the audit directory so all guard state lives in one place.
# The fallback keeps the module self-test runnable as a plain script.
try:
    from . import _store
    from .audit import AUDIT_DIR
except ImportError:  # pragma: no cover - direct script execution
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from qoder_guard import _store
    from qoder_guard.audit import AUDIT_DIR

# Legacy paths, kept so migration and external tooling can find them.
# These are the *default* locations; the migration resolves them from the active
# state directory (see `_legacy_paths`) so an env-var override is honoured.
PENDING_FILE = AUDIT_DIR / "pending_review.jsonl"
APPROVALS_FILE = AUDIT_DIR / "approvals.jsonl"
REVIEWS_DIR = AUDIT_DIR / "reviews"

# Decision values stored in approvals
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"


def _state_dir() -> Path:
    """Active state directory (honours QGUARD_AUDIT_DIR)."""
    return _store.db_path().parent


def _legacy_paths() -> tuple[Path, Path]:
    """(pending, approvals) JSONL paths inside the active state directory."""
    d = _state_dir()
    return d / "pending_review.jsonl", d / "approvals.jsonl"


def _migration_marker() -> Path:
    """Marker file recording that legacy JSONL state was imported."""
    return _state_dir() / ".legacy_review_migrated"


def fingerprint(tool: str, command: str) -> str:
    """Stable id for a tool call: same tool + same command -> same id.

    Normalization is intentionally minimal (strip only) so that two commands
    differing in a meaningful character never share an approval.
    """
    raw = f"{tool}\x00{(command or '').strip()}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def _ensure_dirs() -> None:
    d = _state_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "reviews").mkdir(parents=True, exist_ok=True)


def migrate_legacy_files() -> dict:
    """Import the pre-SQLite JSONL files once; returns counts.

    Runs at most once per state directory (marker file). Individual malformed
    lines are skipped: the migration must never make the queue unreadable.
    """
    counts = {"pending": 0, "approvals": 0}
    marker = _migration_marker()
    if marker.exists():
        return counts

    pending_file, approvals_file = _legacy_paths()

    if pending_file.exists():
        try:
            with open(pending_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not rec.get("id"):
                        continue
                    _store.enqueue_request({
                        "id": rec["id"], "ts": rec.get("ts") or _now(),
                        "tool": rec.get("tool"), "command": rec.get("command"),
                        "reason": rec.get("reason"), "session_id": rec.get("session_id"),
                    })
                    counts["pending"] += 1
        except OSError:
            pass

    if approvals_file.exists():
        try:
            with open(approvals_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not rec.get("id") or rec.get("decision") not in (DECISION_ALLOW, DECISION_DENY):
                        continue
                    _store.record_decision({
                        "id": rec["id"], "ts": rec.get("ts") or _now(),
                        "decision": rec["decision"], "reason": rec.get("reason"),
                        "reviewer": rec.get("reviewer"), "tool": rec.get("tool"),
                        "command": rec.get("command"),
                        "original_reason": rec.get("original_reason"),
                    })
                    counts["approvals"] += 1
        except OSError:
            pass

    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(time.strftime("%Y-%m-%dT%H:%M:%S%z") + "\n", encoding="utf-8")
    except OSError:
        pass
    return counts


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def lookup(fingerprint_id: str) -> dict | None:
    """Return the cached decision for a fingerprint, or None if never decided."""
    migrate_legacy_files()
    return _store.get_decision(fingerprint_id)


def enqueue(tool: str, command: str, reason: str, *, session_id: str | None = None,
            fingerprint_id: str | None = None) -> str:
    """Queue a review request and return its id (the fingerprint).

    Re-queueing the same fingerprint refreshes the existing row, so the queue
    holds one entry per command instead of growing without bound.
    """
    migrate_legacy_files()
    fp = fingerprint_id or fingerprint(tool, command)
    _ensure_dirs()
    _store.enqueue_request({
        "id": fp,
        "ts": _now(),
        "tool": tool,
        "command": command,
        "reason": reason,
        "session_id": session_id,
    })
    return fp


def pending() -> list[dict]:
    """All queued requests that have no decision yet, newest first."""
    migrate_legacy_files()
    return _store.pending_requests()


def resolve(fingerprint_id: str, decision: str, *, reason: str = "",
            reviewer: str = "copilot") -> dict:
    """Record an allow/deny decision for a fingerprint.

    The decision is stored in the approvals table (so the same command is not
    asked again) and the queue entry is closed. A per-decision JSON file is
    still written for the audit trail; failure to write it is not fatal because
    the database is the source of truth.
    """
    if decision not in (DECISION_ALLOW, DECISION_DENY):
        raise ValueError(f"decision must be '{DECISION_ALLOW}' or '{DECISION_DENY}', got {decision!r}")
    migrate_legacy_files()
    _ensure_dirs()

    original = _store.request_by_id(fingerprint_id)
    record = {
        "ts": _now(),
        "id": fingerprint_id,
        "decision": decision,
        "reason": reason,
        "reviewer": reviewer,
        "tool": (original or {}).get("tool"),
        "command": (original or {}).get("command"),
        "original_reason": (original or {}).get("reason"),
    }

    try:
        with open(_state_dir() / "reviews" / f"{fingerprint_id}.json", "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
    except OSError:
        pass

    _store.record_decision(record)
    return record


def stats() -> dict:
    """Counts for a quick overview."""
    migrate_legacy_files()
    return _store.stats()


# -- Self-test -------------------------------------------------------------
if __name__ == "__main__":
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        os.environ["QGUARD_AUDIT_DIR"] = td

        # Same tool + same command -> stable id
        a = fingerprint("Bash", "x=rm; $x -rf /")
        assert a == fingerprint("Bash", "x=rm; $x -rf /")
        assert a != fingerprint("Bash", "x=rm; $x -rf /tmp")
        assert a != fingerprint("Write", "x=rm; $x -rf /")
        assert len(a) == 16

        # Nothing decided yet
        assert lookup(a) is None
        assert pending() == []
        assert stats() == {"pending": 0, "approved": 0, "denied": 0}

        # Enqueue -> appears as pending
        rid = enqueue("Bash", "x=rm; $x -rf /", "command name cannot be resolved", session_id="s1")
        assert rid == a
        p = pending()
        assert len(p) == 1 and p[0]["id"] == a
        assert stats()["pending"] == 1

        # Duplicate enqueue keeps one pending entry
        enqueue("Bash", "x=rm; $x -rf /", "command name cannot be resolved", session_id="s1")
        assert len(pending()) == 1

        # Approve -> cached, queue drains
        rec = resolve(a, DECISION_ALLOW, reason="verified: only touches /tmp", reviewer="copilot")
        assert rec["decision"] == "allow"
        assert lookup(a)["decision"] == "allow"
        assert pending() == []
        assert stats() == {"pending": 0, "approved": 1, "denied": 0}
        assert (Path(td) / "reviews" / f"{a}.json").exists()

        # Deny another fingerprint
        b = fingerprint("Bash", "rm -rf $UNKNOWN")
        resolve(b, DECISION_DENY, reason="cannot verify target")
        assert lookup(b)["decision"] == "deny"
        assert stats() == {"pending": 0, "approved": 1, "denied": 1}

        # Invalid decision is rejected
        try:
            resolve(b, "maybe")
            raise AssertionError("expected ValueError")
        except ValueError:
            pass

        # Last-wins: resolving the same id twice keeps the last decision only.
        # If both rows survived, `approved` would be 2 instead of 1.
        c = fingerprint("Bash", "flip-flop-cmd")
        resolve(c, DECISION_ALLOW, reason="first")
        resolve(c, DECISION_DENY, reason="second")
        assert lookup(c)["decision"] == "deny"
        assert stats() == {"pending": 0, "approved": 1, "denied": 2}

        # A re-queued decided id becomes pending again
        enqueue("Bash", "flip-flop-cmd", "reconsider", session_id="s2")
        assert [r["id"] for r in pending()] == [c]
        assert stats()["pending"] == 1

    # Legacy migration: JSONL files are imported once and then ignored
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        os.environ["QGUARD_AUDIT_DIR"] = td
        tmp.mkdir(parents=True, exist_ok=True)

        (tmp / "pending_review.jsonl").write_text(
            '{"id": "legacy1", "ts": "2026-01-01T00:00:00", "tool": "Bash", '
            '"command": "legacy cmd", "reason": "old"}\n'
            "not valid json\n",
            encoding="utf-8",
        )
        (tmp / "approvals.jsonl").write_text(
            '{"id": "legacy2", "ts": "2026-01-01T00:00:01", "decision": "allow", '
            '"tool": "Bash", "command": "legacy approved"}\n',
            encoding="utf-8",
        )

        counts = migrate_legacy_files()
        assert counts == {"pending": 1, "approvals": 1}, counts
        assert lookup("legacy2")["decision"] == "allow"
        assert [r["id"] for r in pending()] == ["legacy1"]

        # Second call is a no-op thanks to the marker
        assert migrate_legacy_files() == {"pending": 0, "approvals": 0}

    print("review: all assertions passed")
