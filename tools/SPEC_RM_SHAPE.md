# SPEC: `tools/_probe_rm_shape.py` — rm destructive-shape regression matrix

## Context

`qoder_guard/risk.py` currently has ONE regex for `rm`:

```python
Rule(RiskLevel.HIGH, re.compile(r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)?.*", re.I), "deletion")
```

It makes the `-` flag group OPTIONAL and the target `.*` mandatory, so it matches
EVERY `rm` invocation. Audit evidence (803 records): `rm -rf /tmp` graded `high`
(correct), but `rm file.txt` also grades `high` (false positive — a plain file
delete is the same impact class as `mv` / `cp -r` / `git clean`, which are all
MEDIUM in the existing table).

Upstream reference: OpenHands software-agent-sdk (MIT) pins the destructive
shape as **recursive AND force together**:
- `rm -rf /` -> HIGH (concrete destructive shape)
- `rm "-r" file` -> LOW (only one half of the pair)
- `rm -r "$FLAGS" /` -> LOW (dynamic flag word is unknown, not hostile)

## Your task

Create ONE new file: `tools/_probe_rm_shape.py`.

It must be a self-contained regression probe that asserts the grading matrix
below. Do not modify any other file.

## Hard constraints

1. **Only stdlib.** `qoder_guard/` runs on a global Python with zero third-party
   packages; the probe must not import anything outside the stdlib.
2. **All code text in English** — comments, docstrings, strings, variable names.
   No CJK anywhere in the file.
3. **Do not run any shell command.** Write the file only. The caller verifies.
4. **Read-only with respect to guard state.** Import only
   `qoder_guard.risk` — do NOT import `audit`, `review`, or `_store`, so the
   probe cannot write to the production database.
5. Exit code: `0` when every case matches, `1` when any case mismatches.

## Required structure

```python
"""Probe: rm/rmdir destructive-shape grading matrix (see SPEC_RM_SHAPE.md)."""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from qoder_guard.risk import RiskLevel, assess  # noqa: E402

# (command, expected level, why the case is pinned)
CASES: list[tuple[str, RiskLevel, str]] = [ ... ]   # exactly the table below

def main() -> int:
    fails = []
    print("=== rm destructive-shape matrix ===")
    for cmd, expected, why in CASES:
        level, reason = assess("Bash", {"command": cmd})
        ok = level is expected
        print(f"  [{'OK ' if ok else 'BAD'}] {level.value:8} (want {expected.value:8}) {cmd!r}")
        if not ok:
            print(f"        why pinned: {why}")
            print(f"        got reason: {reason}")
            fails.append(f"{cmd!r}: got {level.value}, want {expected.value}")
    print()
    if fails:
        print(f"MISMATCHES ({len(fails)}):")
        for f in fails:
            print("  -", f)
        return 1
    print("_probe_rm_shape: all cases match")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

## The exact case table (do not invent, do not reorder)

| command | expected | why pinned |
|---|---|---|
| `rm file.txt` | MEDIUM | plain delete: same impact class as mv / cp -r / git clean |
| `rm -f file.txt` | MEDIUM | force without recursion is still a single-file delete |
| `rm -i a.txt` | MEDIUM | interactive delete |
| `rm --force a.txt` | MEDIUM | long-form force only, no recursion |
| `rm -r dir` | MEDIUM | recursive without force |
| `rm --recursive dir` | MEDIUM | long-form recursion only |
| `rm -rf dir` | HIGH | recursive AND force together = destructive shape |
| `rm -fr dir` | HIGH | same shape, flags reordered |
| `rm -r -f dir` | HIGH | same shape, separate flag words |
| `rm --recursive --force dir` | HIGH | same shape, long forms |
| `rm -rf /` | HIGH | destructive shape on the root path |
| `rm -rf /tmp` | HIGH | destructive shape (47 audit records) |
| `rm -rf "$DIR"` | HIGH | destructive shape, target is a runtime value |
| `rm -r "$FLAGS" /` | MEDIUM | DEVIATION from upstream: an empty `$FLAGS` makes this `rm -r /` |
| `rm -f "$FLAGS" x` | MEDIUM | DEVIATION from upstream: force plus a runtime flag word |
| `rm "-r" file` | MEDIUM | DEVIATION from upstream: a recursive delete is a bounded side effect |
| `rmdir x` | HIGH | unchanged: existing rmdir rule is out of scope for this fix |
| `echo "unclosed` | LOW | benign string that fails to parse is not uncertain |
| `rm -rf / "unclosed` | HIGH | destructive shape visible in the raw text |
| `rm -r dir "unclosed` | MEDIUM | recursive only, still visible in the raw text |
| `git commit -m "unclosed` | LOW | no destructive shape in the raw text |

`MEDIUM`/`HIGH`/`LOW` above mean `RiskLevel.MEDIUM` / `RiskLevel.HIGH` /
`RiskLevel.LOW`.

## Reporting

In your final message report:
1. the file path you created;
2. any case in the table you believe is contradictory or unimplementable, with
   the reason (do not silently change an expected value);
3. anything in this spec that was ambiguous.

Do not attempt to fix `qoder_guard/risk.py` — the caller implements the
semantics. The probe is expected to FAIL until the caller lands the fix.
