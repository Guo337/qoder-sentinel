"""Find a reliable cross-process append primitive on Windows (stdlib only).

HISTORICAL RECORD. Guard state is now stored in SQLite
(`qoder_guard/_store.py`), which makes this comparison obsolete for the shipped
code -- but it is the evidence behind that decision, so it is kept. The winner
of this comparison (`msvcrt` + sidecar lock file) was the hand-rolled
`_filelock.py` that SQLite replaced.

Candidates:
  text      open(path,"a",encoding=...)            CRT O_APPEND (seek-then-write)
  oswrite   os.open(O_APPEND) + single os.write    also CRT level
  lockfile  os.open(lock,O_CREAT|O_EXCL) spin lock, then text append
  msvcrt    msvcrt.locking(LK_LOCK) on a separate lock file, then text append

Run:  python tools/_probe_append_lock.py
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

WORKER = r'''
import json, os, sys, time
mode, path, start, n = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
lock = path + ".lock"

def append_text(line):
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)

def append_lockfile(line):
    deadline = time.time() + 30
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            if time.time() > deadline:
                raise TimeoutError("lockfile timeout")
            time.sleep(0.002)
    try:
        append_text(line)
    finally:
        os.close(fd)
        try:
            os.unlink(lock)
        except OSError:
            pass

def append_msvcrt(line):
    import msvcrt
    deadline = time.time() + 30
    fd = os.open(lock, os.O_CREAT | os.O_RDWR)
    try:
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                break
            except OSError:
                if time.time() > deadline:
                    raise TimeoutError("msvcrt timeout")
                time.sleep(0.002)
        try:
            append_text(line)
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)

for i in range(start, start + n):
    line = json.dumps({"n": i, "pad": "y" * 120}) + "\n"
    if mode == "text":
        append_text(line)
    elif mode == "oswrite":
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    elif mode == "lockfile":
        append_lockfile(line)
    elif mode == "msvcrt":
        append_msvcrt(line)
print("done")
'''


def run(mode, procs, per):
    with tempfile.TemporaryDirectory() as td:
        state = Path(td)
        wf = state / "w.py"
        wf.write_text(WORKER, encoding="utf-8")
        path = state / "out.jsonl"
        ps = [subprocess.Popen([PY, str(wf), mode, str(path), str(i * per), str(per)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
              for i in range(procs)]
        failed = 0
        for p in ps:
            out, err = p.communicate(timeout=180)
            if p.returncode != 0:
                failed += 1
                if failed == 1:
                    print("   worker err:", err.strip().splitlines()[-1][:120] if err.strip() else "?")
        raw = path.read_text(encoding="utf-8") if path.exists() else ""
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
        return expected, len(lines), good, bad, expected - len(seen), failed


for procs, per in ((4, 50), (8, 25), (12, 30), (16, 25)):
    print(f"=== {procs} processes x {per} writes = {procs * per} ===")
    print("mode      | lines | ok  | corrupt | missing | failed_procs | verdict")
    print("-" * 80)
    for mode in ("text", "oswrite", "lockfile", "msvcrt"):
        exp, ln, good, bad, missing, failed = run(mode, procs, per)
        ok = (bad == 0 and good == exp and failed == 0)
        print(f"{mode:9} | {ln:5} | {good:3} | {bad:7} | {missing:7} | {failed:12} | "
              f"{'OK' if ok else 'LOST'}")
    print()
