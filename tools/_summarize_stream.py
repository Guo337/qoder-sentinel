"""Summarize every event in a Qoder stream-json capture.

Read-only. Writes a one-line-per-event summary plus any event that contains a
security hint, so we can see exactly how the Qoder Security warning is
delivered to the agent.
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
    dst = os.path.join(os.environ.get("TEMP", "."), "l1_all_events.txt")

    lines = []
    for lineno, raw in enumerate(io.open(src, encoding="utf-8-sig", errors="replace"), 1):
        raw = raw.strip()
        if not raw.startswith("{"):
            lines.append(f"{lineno:>3} (non-json) {raw[:160]}")
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            lines.append(f"{lineno:>3} (bad json) {exc} {raw[:160]}")
            continue

        blob = json.dumps(event, ensure_ascii=False)
        keys = ",".join(sorted(event.keys()))
        lines.append(f"{lineno:>3} type={event.get('type')} "
                     f"subtype={event.get('subtype')} len={len(blob)} keys={keys}")

        lowered = blob.lower()
        if any(word in lowered for word in ("probe", "security", "warning", "reminder", "finding")):
            lines.append("    >>> SECURITY-RELATED:")
            lines.append("    " + blob[:1800].replace("\n", "\n    "))
        lines.append("")

    with io.open(dst, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))

    print(f"wrote {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
