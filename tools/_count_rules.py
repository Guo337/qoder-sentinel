"""Count guard rules in qoder_guard to compare against official plugins.

Read-only helper. Prints rule counts and identifiers for risk.py and
sensitive.py so the coverage comparison is grounded in facts.

Usage:
    python tools/_count_rules.py
"""

from __future__ import annotations

import io
import re

RISK = "qoder_guard/risk.py"
SENSITIVE = "qoder_guard/sensitive.py"


def count(path: str) -> None:
    with io.open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    print("=== %s (%d bytes)" % (path, len(text)))
    for label, pattern in (
        ("Rule(", r"Rule\("),
        ("id=", r"id=\"([a-z0-9_]+)\""),
        ("kind=", r"kind=\"([a-z_]+)\""),
    ):
        found = re.findall(pattern, text)
        print("  %-8s %d" % (label, len(found)))
        if found and label != "Rule(":
            print("           %s" % ", ".join(found))
    print("")


def main() -> int:
    for path in (RISK, SENSITIVE):
        count(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
