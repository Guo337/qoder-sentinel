# Task: isolate test/probe audit state from the production audit log

## Context

`qoder_guard/audit.py` resolves its output file from the *module location*:

```python
ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = ROOT / "audit_logs"
AUDIT_FILE = AUDIT_DIR / "qoder_audit.jsonl"
```

Every other guard module reads that path at call time via `audit.log_path()`,
but the in-process test helpers call `hooks.handle_stdin()` directly. That
function calls `audit.append(...)`, which writes to the REAL project audit log.

Measured consequence (2026-09-08): the production log
`audit_logs/qoder_audit.jsonl` contains **37 records with
`event == "hook_bad_input"`** whose `raw` values are `'not json at all'` and
`''` -- these came from `tools/_verify_behavior.py` and `tools/_e2e_hook.py`,
not from Qoder. The log is the raw data layer for the audit panel, so test
noise corrupts a production artifact.

Only 3 tools currently redirect the audit path, and they do it by monkeypatching
module attributes *after import*:

```python
audit.AUDIT_DIR = state
audit.AUDIT_FILE = state / "qoder_audit.jsonl"
```

That is fragile: it must be repeated in every new test, it is easy to forget,
and `audit.log_path()` reads the two globals so a missed assignment silently
writes to production.

## Required change

Make the audit destination overridable by an **environment variable**, so a
test process can isolate itself without monkeypatching, and add a guard so the
mistake is loud rather than silent.

### 1. `qoder_guard/audit.py`

- Add a module-level env var name constant, e.g.
  `AUDIT_DIR_ENV = "QGUARD_AUDIT_DIR"`.
- Resolve the directory lazily in a helper (keep `AUDIT_DIR` / `AUDIT_FILE` /
  `log_path()` working for existing callers):
  - if `os.environ.get(AUDIT_DIR_ENV)` is set and non-empty, use `Path(that)`;
  - otherwise fall back to `ROOT / "audit_logs"`.
- `log_path()` must honour the env var on EVERY call (a test may set it after
  import). Keep creating the directory if missing.
- Add a helper `is_isolated() -> bool` that returns True when the env var is set.
- **Do not change the public API**: `ROOT`, `AUDIT_DIR`, `AUDIT_FILE`,
  `log_path`, `append`, `tail`, `clear` must all still exist and behave as
  before when the env var is unset.
- Update the module docstring to document the env var.

### 2. Test/probe helpers

These call `handle_stdin` or `audit.append` in-process and must isolate:

- `tools/_verify_behavior.py`
- `tools/_probe_debug.py`
- `tools/_probe_whitelist.py`
- `tools/_probe_audit_concurrency.py`
- `tools/_probe_concurrency.py`

For each: set `os.environ["QGUARD_AUDIT_DIR"]` to a temp directory **before**
importing `qoder_guard` modules, and keep the existing monkeypatch assignments
working (they should be harmless, or replace them with the env var if that is
cleaner). Every one of these must leave the real
`Q_explo/audit_logs/qoder_audit.jsonl` byte-identical.

### 3. A regression test

Add `tools/_probe_audit_isolation.py` that:
1. records the size + line count of the real audit log,
2. runs each of the helpers above as a subprocess,
3. asserts the real log is unchanged (same size and line count),
4. asserts each helper still exits 0,
5. prints `_probe_audit_isolation: all assertions passed` and exits 0.

## Hard rules

- Zero third-party dependencies (the hook runs on the global Python 3.11).
- **All code text (comments, docstrings, printed strings) MUST be English.**
- Do NOT touch: `qoder_guard/risk.py`, `qoder_guard/shell_tokens.py`,
  `qoder_guard/hooks.py`, `qoder_guard/policy.py`, `guard/*.py`,
  `tools/_probe_append_*.py`, `tools/_e2e_hook.py`.
- Do NOT delete or rewrite the existing production audit log.

## Verification (all must exit 0)

```
python qoder_guard/audit.py
python guard/verify_setup.py
python tools/_verify_behavior.py
python tools/_probe_debug.py
python tools/_probe_whitelist.py
python tools/_probe_concurrency.py
python tools/_probe_audit_concurrency.py
python tools/_probe_audit_isolation.py
```

Report the exact line count of the real `audit_logs/qoder_audit.jsonl` before
and after your run.
