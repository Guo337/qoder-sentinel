"""Inspect a Qoder `-o stream-json` capture for L1 security warnings.

Read-only. Prints every system/user event and flags any event whose text
mentions the sentinel probe rules, so we can tell whether the Qoder Security
L1 layer injects its warning into the agent context.
"""

from __future__ import annotations

import io
import json
import os
import sys

MARKERS = ("SENTINEL L1 PROBE", "sentinel-l1-proof", "security", "Security")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.environ.get("TEMP", "."), "l1_probe_stream.json"
    )
    hits = 0
    for lineno, raw in enumerate(io.open(path, encoding="utf-8-sig", errors="replace"), 1):
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue

        etype = event.get("type")
        blob = json.dumps(event, ensure_ascii=False)
        marked = [m for m in MARKERS if m in blob]
        if etype in ("system", "user") or marked:
            hits += 1
            print(f"--- line {lineno} type={etype} markers={marked}")
            print(blob[:900])
            print()
    if not hits:
        print("no system/user events and no security markers found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
