"""Concurrency probe for review.py: many processes resolving decisions at once.

What this guards
----------------
The hook runs as a separate process per tool call, so an in-process
`threading.Lock` cannot protect shared state. The original implementation kept
approvals in a read-modify-write JSON object and lost 75% of decisions at 4
processes; a later JSONL rewrite still needed a sidecar lock file to be safe.

State now lives in SQLite (`_store.py`), which serializes writers itself. This
probe asserts that N processes writing N distinct decisions all survive, so a
regression back to hand-rolled file locking would be caught immediately.

Run:  python tools/_probe_concurrency.py
"""
import os
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

# A worker that resolves N distinct fingerprints against a shared state dir.
WORKER = r'''
import os, sys
sys.path.insert(0, r"{root}")
os.environ["QGUARD_AUDIT_DIR"] = sys.argv[1]
from qoder_guard import review
start = int(sys.argv[2]); n = int(sys.argv[3])
for i in range(start, start + n):
    fp = review.fingerprint("Bash", f"cmd-{{i}}")
    review.resolve(fp, review.DECISION_ALLOW, reason="probe", reviewer="probe")
print("done", start, n)
'''

with tempfile.TemporaryDirectory() as td:
    state = Path(td)
    worker_file = state / "worker.py"
    worker_file.write_text(WORKER.format(root=ROOT), encoding="utf-8")

    PROCS, PER = 4, 25
    procs = [
        subprocess.Popen(
            [PY, str(worker_file), str(state), str(i * PER), str(PER)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for i in range(PROCS)
    ]
    for p in procs:
        out, err = p.communicate(timeout=120)
        if p.returncode != 0:
            print("worker failed:", err[-500:])

    expected = PROCS * PER

    # Read the result back through the public API, pointed at the temp state dir.
    sys.path.insert(0, str(ROOT))
    os.environ["QGUARD_AUDIT_DIR"] = str(state)
    from qoder_guard import review  # noqa: E402

    decided = sum(
        1 for i in range(expected)
        if review.lookup(review.fingerprint("Bash", f"cmd-{i}")) is not None
    )
    s = review.stats()
    files = list((state / "reviews").glob("*.json"))

    print(f"expected decisions        : {expected}")
    print(f"decisions readable via API: {decided}")
    print(f"stats()                   : {s}")
    print(f"reviews/*.json files      : {len(files)}")
    print(f"db file                   : {(state / 'guard_state.db').name}")

    failed = False
    if decided != expected:
        failed = True
        print(f"  <-- BUG: LOST UPDATES ({expected - decided} decisions dropped)")
        print("      cause: shared state is not serialized across processes")
    if s["approved"] != expected:
        failed = True
        print(f"  <-- BUG: stats() undercounts approvals ({s['approved']} != {expected})")
    if len(files) != expected:
        failed = True
        print(f"  <-- BUG: review records lost ({expected - len(files)})")

    if failed:
        sys.exit(1)
    print(f"  OK: SQLite serializes {PROCS} concurrent writers, no lost decisions")
    print("\n_probe_concurrency: all assertions passed")

