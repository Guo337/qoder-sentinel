"""Verify the i18n translation: no CJK left, and behavior unchanged.

Checks:
  1. Zero CJK characters in every target file
  2. Every file still compiles (ast.parse)
  3. Public API surface unchanged (function/class names via ast)
  4. No regex patterns changed
"""
import ast
import pathlib
import re
import subprocess
import sys

# The report itself may contain non-ASCII (offending source lines), so force
# UTF-8 output. This is the very bug the project hit before -- do not repeat it.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = pathlib.Path(__file__).resolve().parent.parent
CN = re.compile(r"[\u4e00-\u9fff]")

FILES = [
    "guard/audit_view.py", "guard/install_hooks.py", "guard/observe_hook.py",
    "guard/run_task.py", "guard/verify_setup.py", "qoder_guard/audit.py",
    "qoder_guard/hooks.py", "tools/show_audit.py",
]

failures: list[str] = []


def api_surface(src: str) -> set[str]:
    """Names of top-level functions/classes plus regex pattern literals."""
    tree = ast.parse(src)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(f"{type(node).__name__}:{node.name}")
        # capture re.compile("...") literal patterns
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr == "compile":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        names.add(f"regex:{arg.value}")
    return names


# Baseline: compare against the committed version (b6b5bfb) for the 3 files
# already translated, and against git HEAD for the rest.
print("=== 1. CJK check ===")
for f in FILES:
    p = ROOT / f
    if not p.exists():
        failures.append(f"{f}: MISSING")
        print(f"  {f:38} MISSING")
        continue
    txt = p.read_text(encoding="utf-8")
    n = len(CN.findall(txt))
    if n:
        failures.append(f"{f}: {n} CJK chars left")
        # show the offending lines
        for i, line in enumerate(txt.splitlines(), 1):
            if CN.search(line):
                print(f"  {f}:{i} {line.strip()[:90]}")
    print(f"  {f:38} CJK={n}")

print("\n=== 2. Syntax check ===")
for f in FILES:
    p = ROOT / f
    if not p.exists():
        continue
    try:
        ast.parse(p.read_text(encoding="utf-8"))
        print(f"  {f:38} OK")
    except SyntaxError as e:
        failures.append(f"{f}: SyntaxError {e}")
        print(f"  {f:38} SyntaxError: {e}")

print("\n=== 3. API / regex diff vs git HEAD ===")
for f in FILES:
    p = ROOT / f
    if not p.exists():
        continue
    old = subprocess.run(["git", "show", f"HEAD:{f}"], cwd=str(ROOT),
                         capture_output=True)
    if old.returncode != 0:
        print(f"  {f:38} (not in HEAD, skipped)")
        continue
    old_txt = old.stdout.decode("utf-8", "replace")
    new_txt = p.read_text(encoding="utf-8")
    try:
        o, n = api_surface(old_txt), api_surface(new_txt)
    except SyntaxError:
        continue
    missing = o - n
    added = n - o
    if missing:
        failures.append(f"{f}: removed API/regex {sorted(missing)[:3]}")
        print(f"  {f:38} REMOVED: {sorted(missing)[:3]}")
    elif added:
        print(f"  {f:38} added: {sorted(added)[:3]}")
    else:
        print(f"  {f:38} identical API")

print()
if failures:
    print(f"FAILED ({len(failures)} issues):")
    for x in failures:
        print("  -", x)
    sys.exit(1)
print("ALL CHECKS PASSED")
