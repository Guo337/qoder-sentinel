# Design record: multi-process safe guard state (append-only + real file lock)

> **Superseded (2026-09-08).** The hand-rolled file lock described here
> (`qoder_guard/_filelock.py`) has been removed. Guard state now lives in a
> SQLite database (`qoder_guard/_store.py`, stdlib `sqlite3`, WAL mode), which
> serializes writers itself and needs no sidecar lock file. The measured
> comparison is preserved below and in `_store.py`'s module docstring; the
> original lock-based design is kept here only as the decision record.
>
> Status at the time: implemented and verified. This file started as the task
> spec handed to Qoder CN CLI and is kept as the design record for the
> concurrency fix.
>
> **Correction (important):** the original spec told the implementer to append
> with `open(path, "a", encoding="utf-8")` and claimed that a single `write()`
> makes the append atomic. **That was wrong.** Measured on Windows, a bare
> `open(path, "a")` loses 21-35% of lines under 4 concurrent processes. See
> "Measured primitive comparison" below. The implementation at the time routed
> every append through `qoder_guard/_filelock.py`.

## Problem

`qoder_guard/review.py` stored approvals in a single JSON object
(`approvals.json`). `resolve()` did a read-modify-write guarded only by a
`threading.Lock`. The Qoder hook runs as a SEPARATE PROCESS per tool call, so an
in-process lock cannot span processes. A concurrency probe
(`tools/_probe_concurrency.py`, 4 processes x 25 resolutions) lost 75 of 100
decisions and raised `PermissionError [WinError 32]` on `os.replace` of the temp
file.

`qoder_guard/audit.py` had the same defect and additionally used
`open(path, "a")`, which is itself not atomic across processes.

## Measured primitive comparison

`tools/_probe_append_lock.py`, 4 processes x 100 lines each (400 expected):

| primitive | written | unique | lost | corrupt | verdict |
|---|---|---|---|---|---|
| `open(path, "a", encoding=...)` | 395 | 395 | 5 | 0 | LOST |
| `os.open(O_APPEND)` + `os.write` | 392 | 392 | 8 | 0 | LOST |
| `os.O_CREAT \| os.O_EXCL` spinlock | 375 | 375 | 25 | 2 | LOST (+ PermissionError) |
| `msvcrt.locking(LK_LOCK)` on sidecar `.lock` | 400 | 400 | 0 | 0 | **OK** |

Root cause: the C runtime implements append as *seek to end, then write*. Two
processes can compute the same offset and overwrite each other. `O_APPEND`
narrows the window but does not close it. An `O_EXCL` spinlock loses because the
lock file must be deleted and recreated, and the delete/create pair races.

## Required change (ONLY qoder_guard/review.py)

Replace the whole-file JSON object with an **append-only JSONL log**:

- `APPROVALS_FILE` becomes `APPROVALS_FILE = AUDIT_DIR / "approvals.jsonl"`
- `resolve()` appends ONE line (JSON object) per decision:
  `{"ts":..., "id":..., "decision":..., "reason":..., "reviewer":..., "tool":..., "command":..., "original_reason":...}`
  The append MUST go through `qoder_guard._filelock.append_line()` (which holds
  an `msvcrt.locking` lock on a sidecar `<name>.lock` file). Do NOT read the
  file before appending. Do NOT use a temp file or `os.replace`.
- `_load_approvals()` reads every line, skips blank/malformed lines, and returns
  `{id: record}` where the LAST occurrence of an id wins (append-only replay).
- `lookup()` uses that dict. Keep its signature `lookup(fingerprint_id) -> dict | None`.
- `pending()` must treat an id as decided if it appears in the replay dict.
- `stats()` counts approved/denied from the replay dict (latest wins).
- Keep `reviews/<id>.json` per-decision files as-is (each id is written by one
  decision, so no cross-process contention there). Wrap that write in
  try/except OSError and ignore failure -- the JSONL append is the source of truth.
- `enqueue()` appends to `pending_review.jsonl` via `append_line()` as well.
- Keep the module's public API EXACTLY: `fingerprint`, `lookup`, `enqueue`,
  `pending`, `resolve`, `stats`, `PENDING_FILE`, `APPROVALS_FILE`, `REVIEWS_DIR`,
  `AUDIT_DIR`, `DECISION_ALLOW`, `DECISION_DENY`.
- Keep the `try/except ImportError` fallback import of AUDIT_DIR.
- Zero third-party dependencies. **All code text (comments, docstrings, prints)
  MUST be English** -- this is a hard project rule.

## The lock primitive

`qoder_guard/_filelock.py` (new, stdlib only):

```python
lock_path_for(path) -> Path      # sidecar "<name>.lock"
append_line(path, line) -> None  # open in append mode, msvcrt.locking(LK_LOCK), write, unlock
```

Two design points worth remembering:

1. The lock lives in a **sidecar file**, not the data file. Locking the data file
   itself would prevent Windows from replacing or truncating it.
2. `msvcrt` is imported inside a `try/except ImportError` with a no-op POSIX
   fallback, so the module stays importable on non-Windows hosts.

Timeout is 30s with a 2ms retry interval; a stuck holder raises rather than
hanging the hook forever.

## Self-test requirement
Update the `if __name__ == "__main__":` block:
- Keep every existing assertion working (adjust file names).
- ADD an assertion that resolving the SAME id twice keeps the LAST decision:
  resolve(id, allow) then resolve(id, deny) -> `lookup(id)["decision"] == "deny"`,
  and `stats()["approved"] == 0`, `stats()["denied"] == 1`.
- ADD an assertion that a malformed line in approvals.jsonl is skipped without
  raising.
- Must print exactly `review: all assertions passed` and exit 0.

## Verification (run these, all must pass)

```
python qoder_guard/review.py
python qoder_guard/_filelock.py
python guard/verify_setup.py
python tools/_verify_behavior.py
python tools/_probe_concurrency.py
python tools/_probe_audit_concurrency.py
```

`_probe_concurrency.py` must report 100 approvals / 100 review files.
`_probe_audit_concurrency.py` must report 200/200 records, 0 corrupt.

## Do NOT touch

- `qoder_guard/hooks.py`, `policy.py`, `risk.py`, `shell_tokens.py`
- `guard/*.py`
- any `tools/_probe_*.py`

## Lesson

The spec encoded the wrong primitive, and the implementer followed it
faithfully. **Verify the primitive, not just the API shape.** An append-only
format is only as safe as the append itself.
