"""Compare the official better-harness repo/plugin with this project.

Read-only helper. Reports which plugin manifests declare hooks and whether
the bundled Qoder plugin ships any PreToolUse guardrail.

Usage:
    python tools/_compare_harness.py
"""

from __future__ import annotations

import io
import json
import os

TREE = os.path.join(os.environ.get("TEMP", ""), "bh_tree_full.json")
LOCAL = os.path.join(
    os.environ.get("USERPROFILE", ""),
    ".qoder-cn",
    "plugins",
    "cache",
    "qoder-bundler",
    "better-harness",
    ".qoder-plugin",
    "plugin.json",
)


def main() -> int:
    print("=== plugin.json files in QoderAI/better-harness")
    try:
        with io.open(TREE, "r", encoding="utf-8-sig") as handle:
            tree = json.load(handle)
        for entry in tree["tree"]:
            if entry["path"].endswith("plugin.json"):
                print("  %s" % entry["path"])
    except Exception as exc:  # pragma: no cover - diagnostic helper
        print("  (tree unavailable: %s)" % exc)

    print("")
    print("=== local bundled plugin.json (%s)" % LOCAL)
    try:
        with io.open(LOCAL, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
        print("  keys  : %s" % ", ".join(data.keys()))
        print("  hooks : %s" % data.get("hooks", "(none declared)"))
        print("  skills: %s" % data.get("skills", "(none)"))
    except Exception as exc:  # pragma: no cover - diagnostic helper
        print("  (unavailable: %s)" % exc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
