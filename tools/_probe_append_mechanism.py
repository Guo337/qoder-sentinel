"""Diagnose the append-lost-updates mechanism on Windows.

HISTORICAL RECORD. The audit log and review state are now stored in SQLite
(`qoder_guard/_store.py`), so nothing in the project appends JSONL any more.
This probe is kept because it is the measurement that justified the switch: it
shows that a bare `open(path, "a")` loses lines under concurrent processes.

Run:  python tools/_probe_append_mechanism.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Variant A: plain open(path, "a") -- what audit.py and the review spec use.
# Variant B: os.open with O_APPEND + single os.write (bypasses text buffering).
# Variant C: os.open with O_APPEND + os.write + msvcrt.locking around it.
WORKER = r'''
import json, os, sys, time
mode = sys.argv[1]; path = sys.argv[2]; start = int(sys.argv[3]); n = int(sys.argv[4])
for i in range(start, start + n):
    line = json.dumps({"n": i, "pad": "y" * 120}) + "\n"
    if mode == "text":
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    elif mode == "oswrite":
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    elif mode == "lock":
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        try:
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.lseek(fd, 0, os.SEEK_END)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)
print("done")
'''


def run(mode, procs=4, per=50):
    with tempfile.TemporaryDirectory() as td:
        state = Path(td)
        wf = state / "w.py"
        wf.write_text(WORKER, encoding="utf-8")
        path = state / "out.jsonl"
        ps = [subprocess.Popen([PY, str(wf), mode, str(path), str(i * per), str(per)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
              for i in range(procs)]
        for p in ps:
            out, err = p.communicate(timeout=120)
            if p.returncode != 0:
                print("  worker failed:", err[-300:])
        raw = path.read_text(encoding="utf-8")
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        good, bad, seen = 0, 0, set()
        for ln in lines:
            try:
                rec = json.loads(ln)
                good += 1
                seen.add(rec["n"])
            except json.JSONDecodeError:
                bad += 1
        expected = procs * per
        missing = sorted(set(range(expected)) - seen)
        return expected, len(lines), good, bad, missing


print("mode      | expected | lines | ok  | corrupt | missing | verdict")
print("-" * 78)
for mode in ("text", "oswrite", "lock"):
    exp, ln, good, bad, missing = run(mode)
    verdict = "OK" if (bad == 0 and good == exp) else "LOST UPDATES"
    print(f"{mode:9} | {exp:8} | {ln:5} | {good:3} | {bad:7} | {len(missing):7} | {verdict}")
    if missing and len(missing) <= 12:
        print(f"          | missing ids: {missing}")
