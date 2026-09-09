"""Supervised task runner (stage A).

Drive a qodercn task using headless + stream-json, and relay the event stream:
parse each JSON line, label it, and print -- making "what happens in the terminal"
visible.

Usage (from project root):
  python guard/run_task.py -- "your task description" [--model model_name] [extra qodercn args...]

Examples:
  python guard/run_task.py -- "summarize what's in C:\\Users\\you\\project"
  python guard/run_task.py -- "look at this directory structure" -o text

Notes:
  - In plain-text headless mode, operations requiring confirmation are denied by
    default (official safety design). Stage B will implement "ask me" via the
    stream-json host decision channel.
  - This script only provides visibility; actual allow/block is decided by the
    guard layer (hooks + subsequent gates).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _force_utf8() -> None:
    """Windows console defaults to GBK (cp936); printing emojis etc. causes UnicodeEncodeError.
    Switch stdout/stderr to UTF-8 at runtime (this process only, no settings written)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


import os
import shutil


QODER_BIN_CANDIDATES = [
    # Real binary (qodercn is a .cmd wrapper; CreateProcess cannot execute it directly)
    Path.home() / ".qoder-cn" / "bin" / "qoderclicn" / "qoderclicn.exe",
    Path(os.environ.get("QODER_BIN", "")).expanduser() if os.environ.get("QODER_BIN") else None,
]
QODER_BIN_CANDIDATES = [c for c in QODER_BIN_CANDIDATES if c]


def resolve_binary() -> str:
    """Return the path to a qoder binary that can be directly executed by subprocess.
    Prefers known install location; falls back to qoderclicn.exe on PATH."""
    for cand in QODER_BIN_CANDIDATES:
        if cand.exists():
            return str(cand)
    found = shutil.which("qoderclicn.exe")
    if found:
        return found
    raise FileNotFoundError(
        "qoderclicn.exe not found. Please confirm Qoder CLI is installed (see README)"
    )


def refresh_path() -> str:
    """Merge Machine + User PATH (current session may not see newly installed CLI)."""
    import ctypes
    from ctypes import wintypes

    # Read registry PATH without admin privileges (read once to get full Machine+User merged value)
    # Simpler and more reliable: re-read the registry Environment key's Path (with expansion)
    import winreg

    def _read(hive, subkey, name="Path") -> str:
        try:
            with winreg.OpenKey(hive, subkey) as k:
                val, _ = winreg.QueryValueEx(k, name)
                return str(val)
        except OSError:
            return ""

    machine = _read(winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
    user = _read(winreg.HKEY_CURRENT_USER, r"Environment")
    # REG_EXPAND_SZ returned by winreg is already expanded (QueryValueEx expands %VAR%)
    return (machine + ";" + user).strip(";")


def main() -> int:
    _force_utf8()
    args = sys.argv[1:]
    if not args or args[0] != "--":
        print(__doc__)
        return 2

    # Split: first arg after -- is the task description, rest passed through to qodercn
    rest = args[1:]
    if not rest:
        print("Missing task description", file=sys.stderr)
        return 2
    prompt = rest[0]
    extra = rest[1:]

    # Default output stream-json; user can override with -o text/json
    if not any(a in ("-o", "--output-format") for a in extra):
        extra += ["-o", "stream-json"]

    qoder = resolve_binary()
    cmd = [qoder, "-p", prompt, *extra]
    print(f">> Executing: {cmd}\n", flush=True)

    # Keep full environment, only override PATH (subprocess needs SystemRoot/TEMP etc.)
    env = {**os.environ, "PATH": refresh_path()}
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", env=env, cwd=str(ROOT),
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            _pretty(obj)
        except json.JSONDecodeError:
            print(line, flush=True)  # Non-JSON lines (progress/prompts) passed through as-is

    return proc.wait()


def _pretty(obj: dict) -> None:
    """Label stream-json events with readable tags. Field structure based on testing; unknown types printed as-is."""
    kind = obj.get("type") or obj.get("kind") or "?"
    if kind == "assistant":
        text = obj.get("message") or obj.get("text") or ""
        if text:
            print(f"\n🤖 {text}", flush=True)
        return
    if kind == "result":
        text = obj.get("result") or obj.get("message") or ""
        print(f"\n[RESULT] Result:\n{text}", flush=True)
        return
    if kind == "tool_use":
        name = obj.get("name") or obj.get("tool") or ""
        inp = obj.get("input") or obj.get("tool_input") or ""
        print(f"\n[TOOL] Tool call: {name}: {inp}", flush=True)
        return
    if kind == "permission" or kind == "permission_request":
        print(f"\n[PERM] Permission request: {json.dumps(obj, ensure_ascii=False)[:500]}", flush=True)
        return
    # Unknown event: output as-is for observing actual structure
    print(json.dumps(obj, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    sys.exit(main())
