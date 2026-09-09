"""Observation hook entry point.

Called by the hooks config in Qoder settings.json. Responsibilities:
read stdin event -> write audit log -> allow or block based on config.

Stage A (default): unconditionally allow (exit code 0).
Stage B: set env var QGUARD_BLOCK=1 to enable high-risk blocking (when PreToolUse
        hits HIGH, returns permissionDecision=deny; tested to actually abort the tool call).

Usage (called by Qoder, normally no need to run manually):
  python guard/observe_hook.py
For manual debugging you can pipe in a JSON snippet:
  echo '{"hook_event_name":"PreToolUse",...}' | python guard/observe_hook.py
Enable blocking:
  $env:QGUARD_BLOCK=1   # takes effect for current session
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Make imports find the project root. Derive it from the resolved location of
# THIS file instead of slicing the raw __file__ string: the previous
# `__file__.rsplit(os.sep, 2)[0]`-style bootstrap returned a bare drive letter
# whenever the interpreter reported a path with mixed separators, and a bare
# drive letter resolves against the current working directory -- so the import
# only worked when cwd happened to be the project root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qoder_guard.hooks import handle_stdin  # noqa: E402


def main() -> int:
    # Same as run_task: work around Windows console GBK encoding issues.
    #
    # [IMPORTANT] Must also handle stdin: Qoder sends UTF-8 JSON via stdin, which
    # may contain non-ASCII characters (e.g. Write tool content is non-English source
    # code). On Windows sys.stdin defaults to cp936/GBK; calling read() directly
    # causes UnicodeDecodeError crash -> hook exit code 1 -> audit record lost.
    # Evidence: 2026-09-08 dispatching a .py file with non-ASCII content caused
    # PreToolUse:Write exit_code=1.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    try:
        raw = sys.stdin.read()
    except (UnicodeDecodeError, OSError):
        # Extreme case where even reconfigure cannot save it (e.g. stdin redirected
        # from a binary stream). Fall back to raw buffer; never crash on input
        # failure -- the observer's own failure must not block the task.
        try:
            raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
    # Only block when QGUARD_BLOCK=1; default is pure observation, never block tasks
    block = os.environ.get("QGUARD_BLOCK", "").strip() in ("1", "true", "yes")
    return handle_stdin(raw, block_high_risk=block)


if __name__ == "__main__":
    sys.exit(main())
