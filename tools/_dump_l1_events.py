"""Dump all Qoder Security hook events from a stream-json capture to a report.

Read-only. Writes a compact report next to the capture so it can be read with
a normal file read instead of fighting PowerShell multi-line quoting.
"""

from __future__ import annotations

import io
import json
import os
import sys


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.environ.get("TEMP", "."), "l1_probe_stream.json"
    )
    dst = os.path.join(os.environ.get("TEMP", "."), "l1_events_report.txt")

    lines = []
    for lineno, raw in enumerate(io.open(src, encoding="utf-8-sig", errors="replace"), 1):
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue

        etype = event.get("type")
        subtype = event.get("subtype")
        hook = event.get("hook_name") or ""
        if etype != "system" and "hook" not in json.dumps(event)[:200]:
            continue
        if "PostToolUse" not in json.dumps(event):
            continue

        lines.append(f"=== line {lineno} type={etype} subtype={subtype} "
                     f"hook={hook} exit={event.get('exit_code')} "
                     f"outcome={event.get('outcome')}")
        for key in ("output", "stdout", "stderr", "additionalContext", "content"):
            value = event.get(key)
            if isinstance(value, str) and value.strip():
                lines.append(f"  [{key}] len={len(value)}")
                lines.append("  " + value.replace("\n", "\n  ")[:2500])
        lines.append("")

    with io.open(dst, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) or "(no PostToolUse events found)\n")

    print(f"wrote {dst} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
