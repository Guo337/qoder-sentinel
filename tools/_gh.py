"""Tiny helper: run `gh api <path>` and print selected JSON fields.

Usage: python tools\\_gh.py <api-path> <mode>
  mode = issues | repos | raw

Kept in the repo because PowerShell quoting of `gh --jq` is unreliable on
Windows (the shell splits arguments containing spaces or backslashes).
"""

from __future__ import annotations

import json
import subprocess
import sys


def fetch(api_path: str) -> object:
    out = subprocess.run(
        ["gh", "api", api_path],
        capture_output=True,
        check=True,
    ).stdout
    return json.loads(out.decode("utf-8"))


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    api_path, mode = sys.argv[1], sys.argv[2]
    data = fetch(api_path)

    if mode == "issues":
        for row in data:
            kind = "PR" if "pull_request" in row else "ISSUE"
            print(f"{row['number']:>4} {row['state']:<6} {kind:<5} {row['title']}")
    elif mode == "repos":
        for row in data:
            lic = (row.get("license") or {}).get("spdx_id") or "-"
            print(f"{row['full_name']:<45} {row.get('language') or '-':<10} "
                  f"{row.get('stargazers_count', 0):>6} {lic:<12} {row.get('description') or '-'}")
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2)[:8000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
