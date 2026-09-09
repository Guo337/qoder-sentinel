"""Extract the Qoder Security L1 warning text from a stream-json capture.

Read-only. Looks for PostToolUse hook output containing the sentinel probe
marker and prints the surrounding text, proving the warning reaches the agent.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys

PROBE = re.compile(r".{0,240}PROBE.{0,600}", re.S)


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.environ.get("TEMP", "."), "l1_probe_stream.json"
    )
    found = 0
    for lineno, raw in enumerate(io.open(path, encoding="utf-8-sig", errors="replace"), 1):
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue

        output = event.get("output") or ""
        if "PROBE" not in output:
            continue

        found += 1
        print(f"=== line {lineno} subtype={event.get('subtype')} "
              f"hook={event.get('hook_name')} output_len={len(output)}")
        match = PROBE.search(output)
        print(match.group(0) if match else output[:600])
        print()

    print(f"events carrying the probe warning: {found}")
    return 0 if found else 1


if __name__ == "__main__":
    raise SystemExit(main())
