"""Print every hook event from a Qoder CLI stream-json capture.

Reads a capture file produced by:
    qodercn -p "..." -o stream-json *> capture.json

Reports hook_started / hook_response / hook_progress entries with their
exit codes and output, so failures (e.g. exit 127) are easy to spot.

Usage:
    python tools/_hook_report.py <capture.json>
"""

from __future__ import annotations

import io
import json
import sys


def _detect_encoding(path: str) -> str:
    """Sniff a BOM so PowerShell redirects (UTF-16) also parse."""
    with open(path, "rb") as handle:
        head = handle.read(4)
    if head.startswith(b"\xff\xfe") and not head.startswith(b"\xff\xfe\x00\x00"):
        return "utf-16-le"
    if head.startswith(b"\xfe\xff"):
        return "utf-16-be"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def load_events(path: str) -> list[dict]:
    """Parse newline-delimited JSON, tolerating BOMs and blank lines."""
    encoding = _detect_encoding(path)
    with io.open(path, "r", encoding=encoding, errors="replace") as handle:
        raw = handle.read()
    if raw.startswith("\ufeff"):
        raw = raw[1:]
    events: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python tools/_hook_report.py <capture.json>")
        return 2
    events = load_events(sys.argv[1])
    print("total events: %d" % len(events))
    hooks: dict[str, dict] = {}
    for event in events:
        if event.get("type") != "system":
            continue
        subtype = event.get("subtype")
        if subtype not in ("hook_started", "hook_response", "hook_progress"):
            continue
        hook_id = event.get("hook_id", "?")
        slot = hooks.setdefault(hook_id, {"name": event.get("hook_name", "?"), "events": []})
        if event.get("hook_name"):
            slot["name"] = event["hook_name"]
        slot["events"].append(event)

    if not hooks:
        print("no hook events found")
        return 0

    bad = 0
    for hook_id, slot in hooks.items():
        print("")
        print("hook_id   : %s" % hook_id)
        print("name      : %s" % slot["name"])
        for event in slot["events"]:
            subtype = event.get("subtype")
            if subtype == "hook_started":
                print("  started : %s" % event.get("command", ""))
            elif subtype == "hook_progress":
                out = (event.get("output") or "").strip()
                if out:
                    print("  progress: %s" % out.replace("\n", " | ")[:400])
            else:
                code = event.get("exit_code")
                print("  response: exit_code=%s" % code)
                for key in ("stdout", "stderr", "output"):
                    text = (event.get(key) or "").strip()
                    if text:
                        print("    %s: %s" % (key, text.replace("\n", " | ")[:600]))
                if code not in (0, None):
                    bad += 1
    print("")
    print("hooks with non-zero exit: %d" % bad)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
