"""Enable the Qoder Security plugin (security-scan) for both CLI and IDE.

Read-only by default; pass --apply to write. Writes only user-level config
under the user's own profile, so no administrator rights are required.

Targets:
  1. ~/.qoder-cn/settings.json          -> enabledPlugins + securityScan
  2. %APPDATA%/QoderCN/.../app-config.json -> securityScan

Every file is backed up next to the original before it is modified.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import time

PLUGIN_ID = "security-scan@qoder-bundler"
SCAN_KEYS = ("enabled", "l1StaticCheck", "l2LightweightScan", "l3DeepScan")

CLI_SETTINGS = os.path.join(os.path.expanduser("~"), ".qoder-cn", "settings.json")
IDE_CONFIG = os.path.join(
    os.environ.get("APPDATA", ""),
    "QoderCN",
    "SharedClientCache",
    "cache",
    "app-config.json",
)


def load(path: str) -> dict:
    with io.open(path, encoding="utf-8") as handle:
        return json.load(handle)


def backup(path: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = f"{path}.bak-sentinel-{stamp}"
    shutil.copy2(path, target)
    return target


def diff(before: dict, after: dict, keys) -> str:
    parts = []
    for key in keys:
        old, new = before.get(key), after.get(key)
        if old != new:
            parts.append(f"{key}: {old} -> {new}")
    return "; ".join(parts) if parts else "(no change)"


def plan_cli(data: dict) -> tuple[dict, str]:
    before_plugins = dict(data.get("enabledPlugins", {}))
    before_scan = dict(data.get("securityScan", {}))
    data.setdefault("enabledPlugins", {})[PLUGIN_ID] = True
    data.setdefault("securityScan", {}).update({k: True for k in SCAN_KEYS})
    note = diff(
        {"enabledPlugins": before_plugins, "securityScan": before_scan},
        {"enabledPlugins": data["enabledPlugins"], "securityScan": data["securityScan"]},
        ("enabledPlugins", "securityScan"),
    )
    return data, note


def plan_ide(data: dict) -> tuple[dict, str]:
    before_scan = dict(data.get("securityScan", {}))
    data.setdefault("securityScan", {}).update({k: True for k in SCAN_KEYS})
    return data, diff({"securityScan": before_scan}, data, ("securityScan",))


def main() -> int:
    apply = "--apply" in sys.argv
    mode = "APPLY" if apply else "DRY RUN"
    print(f"mode: {mode}")
    print(f"admin required: no (user-level config only)\n")

    targets = [
        ("CLI settings", CLI_SETTINGS, plan_cli),
        ("IDE config  ", IDE_CONFIG, plan_ide),
    ]

    for label, path, planner in targets:
        print(f"--- {label}: {path}")
        if not os.path.exists(path):
            print("    SKIP: file not found\n")
            continue

        original = load(path)
        updated, note = planner(json.loads(json.dumps(original)))
        print(f"    {note}")

        if apply:
            saved = backup(path)
            with io.open(path, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(updated, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            print(f"    written; backup: {os.path.basename(saved)}")
        print()

    if not apply:
        print("Re-run with --apply to write the changes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
