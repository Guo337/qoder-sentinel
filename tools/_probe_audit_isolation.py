"""Regression test: test/probe helpers must not write to production state.

Records the real state database's size and row counts, runs each helper as a
subprocess, then asserts nothing changed.

Run:  python tools/_probe_audit_isolation.py
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable

HELPERS = [
    "tools/_verify_behavior.py",
    "tools/_e2e_hook.py",
    "tools/_probe_debug.py",
    "tools/_probe_whitelist.py",
    "tools/_probe_upstream_parity.py",
    "tools/_probe_rm_shape.py",
    "tools/_probe_structural_escapes.py",
    "tools/_probe_shell_ast.py",
    "tools/_probe_bypass_matrix.py",
    "tools/_probe_false_positive.py",
    "tools/_probe_path_independence.py",
    "tools/_probe_concurrency.py",
    "tools/_probe_audit_concurrency.py",
    "guard/verify_setup.py",
]

DB_FILE = ROOT / "audit_logs" / "guard_state.db"


def db_stats() -> tuple[int, int, int]:
    """Return (size_bytes, audit_rows, review_rows) of the production state db.

    Sizes of the -wal/-shm sidecars are excluded: SQLite may checkpoint them at
    any time, so they are not a stable signal. Row counts are the real check.
    """
    if not DB_FILE.exists():
        return (0, 0, 0)
    size = DB_FILE.stat().st_size
    sys.path.insert(0, str(ROOT))
    from qoder_guard import _store  # noqa: PLC0415
    con = _store.connect()
    try:
        audit_rows = con.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        review_rows = con.execute(
            "SELECT COUNT(*) FROM review_requests"
        ).fetchone()[0]
    finally:
        con.close()
    return (size, audit_rows, review_rows)


def main() -> None:
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    before_size, before_audit, before_reviews = db_stats()
    print(f"state db before: size={before_size} audit_rows={before_audit} "
          f"review_rows={before_reviews}")

    fails: list[str] = []
    for helper in HELPERS:
        script = ROOT / helper
        print(f"running {helper} ...")
        try:
            proc = subprocess.run(
                [PY, str(script)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            fails.append(f"{helper}: timed out after 180s")
            print(f"  TIMEOUT")
            continue

        if proc.returncode != 0:
            fails.append(f"{helper}: exit {proc.returncode}")
            print(f"  FAILED (exit {proc.returncode})")
            if proc.stderr:
                print(f"  stderr: {proc.stderr[-300:]}")
        else:
            print(f"  OK (exit 0)")

    after_size, after_audit, after_reviews = db_stats()
    print(f"\nstate db after: size={after_size} audit_rows={after_audit} "
          f"review_rows={after_reviews}")

    if after_audit != before_audit:
        fails.append(f"audit rows changed: {before_audit} -> {after_audit}")
    if after_reviews != before_reviews:
        fails.append(f"review rows changed: {before_reviews} -> {after_reviews}")

    if fails:
        print(f"\nFAILED ({len(fails)}):")
        for f in fails:
            print(f"  - {f}")
        sys.exit(1)

    print("\n_probe_audit_isolation: all assertions passed")


if __name__ == "__main__":
    main()
