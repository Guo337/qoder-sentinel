"""Measure: how much code is ours, how much is borrowed, what do we depend on?

Read-only analysis of the Q_explo tree. Writes its report to
tools/_code_stats_out.txt so PowerShell redirection cannot mangle the encoding.
"""
from __future__ import annotations

import ast
import collections
import io
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.stdout = io.StringIO()


def out(*a):
    print(*a)


STDLIB = set(sys.stdlib_module_names)

# Third-party packages installed in the interpreter, if any are importable.
try:
    import importlib.metadata as md

    INSTALLED = {d.metadata["Name"].lower().replace("-", "_") for d in md.distributions() if d.metadata["Name"]}
except Exception:
    INSTALLED = set()

py_files = sorted(p for p in ROOT.rglob("*.py") if ".venv" not in p.parts and "site-packages" not in p.parts)


def bucket(p: pathlib.Path) -> str:
    rel = p.relative_to(ROOT)
    if rel.parts[0] == "guard":
        return "guard/ (CLI entry points)"
    if rel.parts[0] == "qoder_guard":
        return "qoder_guard/ (core logic)"
    if rel.parts[0] == "tools":
        return "tools/ (probes + analyzers)"
    if rel.parts[0] == "tests":
        return "tests/"
    return "other"


lines = collections.Counter()
files = collections.Counter()
total_lines = 0
for p in py_files:
    try:
        n = len(p.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        continue
    b = bucket(p)
    lines[b] += n
    files[b] += 1
    total_lines += n

out("=== lines of Python by area ===")
for b, n in lines.most_common():
    out(f"  {b:32} {n:6} lines in {files[b]:3} files")
out(f"  {'TOTAL':32} {total_lines:6} lines in {sum(files.values()):3} files")

out()
out("=== imports: stdlib vs local vs third-party ===")
ext = collections.Counter()
local = collections.Counter()
std = collections.Counter()
parse_fail = []
for p in py_files:
    try:
        tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError as e:
        parse_fail.append((p, e))
        continue
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            mods = [node.module]
        for m in mods:
            top = m.split(".")[0]
            if top in ("qoder_guard", "guard", "tools"):
                local[top] += 1
            elif top in STDLIB:
                std[top] += 1
            else:
                ext[top] += 1

out(f"  stdlib modules used : {len(std)} distinct")
out(f"    {', '.join(sorted(std))}")
out(f"  local modules       : {dict(local)}")
out(f"  THIRD-PARTY imports : {len(ext)} distinct -> {dict(ext) if ext else '(none)'}")
for m in ext:
    out(f"    {m}: {'installed' if m in INSTALLED else 'NOT installed in this interpreter'}")
if parse_fail:
    out(f"  parse failures: {[(str(p.relative_to(ROOT)), str(e)[:60]) for p, e in parse_fail]}")

out()
out("=== test/probe code vs shipped code ===")
shipped = lines["guard/ (CLI entry points)"] + lines["qoder_guard/ (core logic)"]
probe = lines["tools/ (probes + analyzers)"]
out(f"  shipped guard code : {shipped}")
out(f"  probes/analyzers   : {probe}")
if shipped:
    out(f"  ratio              : {probe / shipped:.2f} lines of test tooling per line of guard code")

pathlib.Path("tools/_code_stats_out.txt").write_text(sys.stdout.getvalue(), encoding="utf-8")
sys.stdout = sys.__stdout__
print("wrote tools/_code_stats_out.txt")
