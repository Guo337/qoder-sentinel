"""Audit Qoder plugin settings across the settings.json backups.

Read-only. Prints, for every settings.json* snapshot, which plugins are
enabled and what the securityScan switches look like, so we can tell when a
plugin was switched off and by what.
"""

from __future__ import annotations

import glob
import io
import json
import os
import time

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".qoder-cn")
WATCH = ("security-scan@qoder-bundler", "computer-use@qoder-bundler")


def describe(path: str) -> None:
    try:
        data = json.load(io.open(path, encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report and continue
        print(f"{os.path.basename(path):<42} UNREADABLE ({exc})")
        return

    enabled = data.get("enabledPlugins", {})
    scan = data.get("securityScan", {})
    flags = " ".join(f"{k}={v}" for k, v in sorted(scan.items()))
    state = " ".join(f"{name.split('@')[0]}={enabled.get(name)}" for name in WATCH)
    mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(path)))
    print(f"{os.path.basename(path):<42} {mtime}  {state:<44} {flags}")


def main() -> int:
    print(f"config dir: {CONFIG_DIR}")
    print(f"{'file':<42} {'mtime':<20} {'plugins':<44} securityScan")
    print("-" * 150)
    for path in sorted(glob.glob(os.path.join(CONFIG_DIR, "settings.json*"))):
        describe(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
