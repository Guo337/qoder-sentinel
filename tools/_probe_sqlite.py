"""Measure: is stdlib sqlite3 actually safe for many concurrent writer processes?

Before replacing the custom _filelock.py with SQLite, verify the primitive the
same way we verified (and rejected) the append-mode file write. If this probe
loses rows, the replacement plan is wrong.

Read-only w.r.t. the project: uses a temp database.
"""
from __future__ import annotations

import io
import pathlib
import sqlite3
import subprocess
import sys
import tempfile

sys.stdout = io.StringIO()

WORKER = r'''
import sqlite3, sys
db, start, n, mode = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
con = sqlite3.connect(db, timeout=30.0, isolation_level=None)
con.execute("PRAGMA journal_mode=WAL")
con.execute("PRAGMA busy_timeout=30000")
con.execute("PRAGMA synchronous=NORMAL")
for i in range(start, start + n):
    if mode == "implicit":
        con.execute("INSERT INTO t(n, pad) VALUES (?, ?)", (i, "x" * 200))
    else:
        con.execute("BEGIN IMMEDIATE")
        con.execute("INSERT INTO t(n, pad) VALUES (?, ?)", (i, "x" * 200))
        con.execute("COMMIT")
con.close()
'''


def run(procs: int, per: int, mode: str) -> tuple[int, int, int]:
    with tempfile.TemporaryDirectory() as td:
        db = pathlib.Path(td) / "t.db"
        wf = pathlib.Path(td) / "w.py"
        wf.write_text(WORKER, encoding="utf-8")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE t(n INTEGER PRIMARY KEY, pad TEXT)")
        con.commit()
        con.close()

        ps = [
            subprocess.Popen([sys.executable, str(wf), str(db), str(i * per), str(per), mode],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for i in range(procs)
        ]
        errs = []
        for p in ps:
            _o, e = p.communicate(timeout=180)
            if p.returncode != 0:
                errs.append(e.strip().splitlines()[-1][:120] if e.strip() else f"exit={p.returncode}")

        con = sqlite3.connect(db)
        total = con.execute("SELECT COUNT(*) FROM t").fetchone()[0]
        distinct = con.execute("SELECT COUNT(DISTINCT n) FROM t").fetchone()[0]
        con.close()
        return total, distinct, len(errs)


print("=== sqlite3 concurrent inserts (expected = procs * per) ===")
print(f"{'mode':10} {'procs':>5} {'expected':>9} {'rows':>7} {'distinct':>9} {'errors':>7} verdict")
bad = 0
for mode in ("implicit", "immediate"):
    for procs, per in ((4, 100), (8, 100), (16, 50)):
        exp = procs * per
        total, distinct, nerr = run(procs, per, mode)
        ok = total == exp and distinct == exp and nerr == 0
        if not ok:
            bad += 1
        print(f"{mode:10} {procs:5} {exp:9} {total:7} {distinct:9} {nerr:7} {'OK' if ok else 'LOST'}")

print()
print(f"-> {bad} failing configuration(s)")
report = sys.stdout.getvalue()
sys.stdout = sys.__stdout__
pathlib.Path("tools/_probe_sqlite_out.txt").write_text(report, encoding="utf-8")
print(f"probe done: {bad} failing configuration(s); see tools/_probe_sqlite_out.txt")
