"""Concurrency probe for audit.py: many processes appending at once.

The audit log used to be a JSONL file written with a bare `open(path, "a")`,
which lost 21-35% of records when several hooks wrote simultaneously. It is now
a SQLite table (`_store.py`), which serializes writers itself. This probe
asserts that N processes writing N distinct records all survive, and that the
first-use WAL switch does not drop a process.

Run:  python tools/_probe_audit_concurrency.py
"""
import json
import pathlib
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

WORKER = r'''
import os, sys
sys.path.insert(0, r"{root}")
os.environ["QGUARD_AUDIT_DIR"] = sys.argv[1]
from qoder_guard import audit
start = int(sys.argv[2]); n = int(sys.argv[3])
for i in range(start, start + n):
    audit.append({{"event": "probe", "n": i, "pad": "x" * 200}})
print("done")
'''

with tempfile.TemporaryDirectory() as td:
    state = Path(td)
    wf = state / "worker.py"
    wf.write_text(WORKER.format(root=ROOT), encoding="utf-8")

    PROCS, PER = 4, 50
    procs = [
        subprocess.Popen([PY, str(wf), str(state), str(i * PER), str(PER)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for i in range(PROCS)
    ]
    worker_errors = 0
    for p in procs:
        out, err = p.communicate(timeout=120)
        if p.returncode != 0:
            worker_errors += 1
            print("worker failed:", err[-400:])

    expected = PROCS * PER

    # Read the records back through the public API, pointed at the temp dir.
    import os
    sys.path.insert(0, str(ROOT))
    os.environ["QGUARD_AUDIT_DIR"] = str(state)
    from qoder_guard import audit  # noqa: E402

    total = audit.count()
    seen = {r.get("n") for r in audit.all_records() if r.get("event") == "probe"}

    print(f"expected {expected} records")
    print(f"worker failures  : {worker_errors}")
    print(f"records in db    : {total}")
    print(f"unique records   : {len(seen)}")

    if worker_errors or len(seen) != expected or total != expected:
        print("  <-- BUG: audit log corrupted or lost records")
        sys.exit(1)
    print(f"  OK: SQLite serializes {PROCS} concurrent writers, no lost records")
    print("\n_probe_audit_concurrency: all assertions passed")
