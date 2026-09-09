"""Audit log engine.

Appends every observed Qoder tool call/event to the guard state database
(`guard_state.db`, SQLite -- see `_store.py` for why SQLite replaced the
hand-rolled JSONL append).

`qoder_guard/audit.py` stays the public entry point so callers do not care where
the bytes land. `audit_logs/qoder_audit.jsonl` is no longer written; use
`export_jsonl()` to produce it on demand (external tools, archives).

Audit log directory: <project_root>/audit_logs/
(independent of Qoder's own conversation logs -- this is the raw data layer for
the "execution audit panel" that Qoder lacks)

Environment variable override:
    QGUARD_AUDIT_DIR  -- if set and non-empty, state is written to
                         <QGUARD_AUDIT_DIR>/ instead of the default
                         <project_root>/audit_logs/. Used by test and probe
                         helpers to isolate their output from production state.
                         See is_isolated().
"""
from __future__ import annotations

import os
from pathlib import Path

from . import _store

AUDIT_DIR_ENV = _store.AUDIT_DIR_ENV

# Project root = two levels up from this file (qoder_guard/ -> project root)
ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = ROOT / "audit_logs"
AUDIT_FILE = AUDIT_DIR / "qoder_audit.jsonl"  # legacy path, kept for export
STATE_FILE = AUDIT_DIR / _store.DB_NAME


def _resolve_dir() -> Path:
    """Return the state directory, honouring the env-var override."""
    return _store.resolve_dir()


def log_path() -> Path:
    """Return the state database path (creates directory automatically).

    Honours QGUARD_AUDIT_DIR on every call so a test may set it after import.
    """
    d = _resolve_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / _store.DB_NAME


def is_isolated() -> bool:
    """Return True when the state destination is overridden via env var."""
    return bool(os.environ.get(AUDIT_DIR_ENV))


def append(record: dict) -> None:
    """Append an audit record (atomic across processes).

    Field conventions (stage A records at least these):
      ts         timestamp
      event      event name (PreToolUse / PostToolUse / PostToolUseFailure ...)
      session_id session ID
      cwd        working directory
      agent_id   triggering agent (if provided)
      tool       tool name (Bash / Edit / Write / MCP tool ...)
      tool_input raw tool arguments (command content etc.)
      risk       risk assessment result (recorded from stage A onward; used for blocking in stage B)
    """
    _store.append_audit(record)


def tail(n: int = 30) -> list[dict]:
    """Read the last n audit records (for verification/replay)."""
    return _store.recent_audit(n)


def count() -> int:
    """Total number of audit records."""
    return _store.count_audit()


def all_records() -> list[dict]:
    """Every audit record, oldest first (for aggregate views)."""
    return _store.all_audit()


def clear() -> None:
    """Clear the audit log (for debugging; use with care)."""
    _store.clear_audit()


def export_jsonl(path: Path | None = None) -> int:
    """Export the audit table as JSONL; returns the number of records written."""
    return _store.export_jsonl(path or log_path().with_name("qoder_audit.jsonl"))
