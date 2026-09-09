"""Probe: the tree-sitter AST layer (qoder_guard/shell_ast.py) contract.

Read-only. Exit 0 only if every assertion holds.

This probe is the acceptance test for a ported component. It checks the two
properties the grading engine depends on:

  1. `iter_commands` finds EVERY command in the tree, including commands nested
     inside shell structure (subshell, if/for/while/case, function body,
     assignment prefix). Missing nested commands is exactly the bug this layer
     exists to fix.
  2. `parse_ok` / `opaque_head` report parse failure and unresolvable command
     names without ever raising.

It also checks the degradation path: when the grammar is unavailable the module
must still import and return safe values instead of crashing the hook.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qoder_guard import shell_ast  # noqa: E402


# (source, expected command texts in source order, description)
NESTING_CASES: list[tuple[str, list[str], str]] = [
    ("echo hi", ["echo hi"], "flat command"),
    ("ls -la && echo hi", ["ls -la", "echo hi"], "and chain"),
    ("(rm -rf /)", ["rm -rf /"], "subshell"),
    ("( ( rm -rf / ) )", ["rm -rf /"], "nested subshell"),
    ("{ rm -rf /; }", ["rm -rf /"], "compound statement"),
    ("! rm -rf /", ["rm -rf /"], "negated command"),
    ("FOO=bar rm -rf /", ["FOO=bar rm -rf /"], "assignment prefix (single node)"),
    ("x=1 y=2 rm -rf /tmp", ["x=1 y=2 rm -rf /tmp"], "two assignment prefixes (single node)"),
    ("if true; then rm -rf /; fi", ["true", "rm -rf /"], "if body"),
    ("for f in *; do rm -rf $f; done", ["rm -rf $f"], "for body"),
    ("while true; do rm -rf /; done", ["true", "rm -rf /"], "while body"),
    ("until false; do rm -rf /; done", ["false", "rm -rf /"], "until body"),
    ("case x in x) rm -rf /;; esac", ["rm -rf /"], "case item"),
    ("f() { rm -rf /; }; f", ["rm -rf /", "f"], "function body plus call"),
    ("sudo (rm -rf /)", ["sudo (rm -rf /)", "rm -rf /"], "subshell as argument"),
    ("echo $(rm -rf /)", ["echo $(rm -rf /)", "rm -rf /"], "command substitution"),
    ("true | rm -rf /", ["true", "rm -rf /"], "pipeline"),
]

# (source, expected resolved command name, expected assignments, description)
NAME_CASES: list[tuple[str, str | None, tuple[str, ...], str]] = [
    ("rm -rf /", "rm", (), "plain command"),
    ("/bin/rm -rf /", "/bin/rm", (), "absolute path"),
    ("FOO=bar rm -rf /", "rm", ("FOO=bar",), "assignment prefix is split off"),
    ("x=1 y=2 rm -rf /tmp", "rm", ("x=1", "y=2"), "two assignments split off"),
    ("if true; then rm -rf /; fi", "true", (), "first node is the condition"),
    ("$x -rf /", "$x", (), "opaque name is still reported"),
]


# (source, expected opaque command name or None, description)
OPAQUE_CASES: list[tuple[str, str | None, str]] = [
    ("rm -rf /", None, "resolvable name"),
    ("/bin/rm -rf /", None, "absolute path name"),
    ("FOO=bar rm -rf /", None, "assignment prefix, name still resolvable"),
    ("$x -rf /", "$x", "opaque variable name"),
    ("$(echo rm) -rf /", "$(echo rm)", "opaque substitution name"),
    ("`whoami` -rf /", "`whoami`", "opaque backtick name"),
    ("echo $HOME", None, "opaque ARGUMENT only, name resolvable"),
    ("echo *.py", None, "glob argument only"),
    ("rm -rf C:\\Users\\test\\temp", None, "windows path is not opaque"),
]

PARSE_CASES: list[tuple[str, bool, str]] = [
    ("rm -rf /", True, "plain command parses"),
    ("if true; then echo hi; fi", True, "structured command parses"),
    ("unclosed 'quote", False, "unterminated quote fails"),
    ('unclosed "quote', False, "unterminated double quote fails"),
    ("", False, "empty string does not parse"),
]


def _run_isolated_import_check() -> tuple[bool, str]:
    """Import the module with the grammar hidden, to exercise the fallback.

    A hook must never crash because a dependency is missing, so the degraded
    path is part of the contract, not an afterthought.
    """
    code = (
        "import sys, importlib.abc, importlib\n"
        "class Blocker(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in ('tree_sitter', 'tree_sitter_bash'):\n"
        "            raise ImportError('blocked for test')\n"
        "        return None\n"
        "sys.meta_path.insert(0, Blocker())\n"
        f"sys.path.insert(0, r'{ROOT}')\n"
        "from qoder_guard import shell_ast\n"
        "assert shell_ast.AVAILABLE is False, 'AVAILABLE must be False'\n"
        "assert shell_ast.iter_commands('rm -rf /') == (), 'must return empty tuple'\n"
        "assert shell_ast.parse_ok('rm -rf /') is False, 'must report not-ok'\n"
        "assert shell_ast.opaque_head('rm -rf /') is None, 'must return None'\n"
        "print('DEGRADED_OK')\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    return (proc.returncode == 0 and "DEGRADED_OK" in proc.stdout,
            (proc.stdout + proc.stderr).strip())


def main() -> int:
    failures: list[str] = []

    if not shell_ast.AVAILABLE:
        print("FAIL grammar unavailable: tree-sitter is not importable")
        return 1
    print("grammar available: True")

    print()
    print("-- nesting --")
    for source, expected, note in NESTING_CASES:
        got = [c.text for c in shell_ast.iter_commands(source)]
        ok = got == expected
        if not ok:
            failures.append(f"nesting {source!r}: want {expected} got {got}")
        print(f"  {'ok  ' if ok else 'FAIL'} {source:34} -> {got}   ({note})")

    print()
    print("-- name extraction --")
    for source, want_name, want_assignments, note in NAME_CASES:
        commands = shell_ast.iter_commands(source)
        got_name = commands[0].name if commands else None
        got_assignments = commands[0].assignments if commands else ()
        ok = got_name == want_name and got_assignments == want_assignments
        if not ok:
            failures.append(
                f"name {source!r}: want name={want_name!r} assignments={want_assignments} "
                f"got name={got_name!r} assignments={got_assignments}"
            )
        print(f"  {'ok  ' if ok else 'FAIL'} {source:34} -> name={got_name!r} "
              f"assignments={got_assignments}   ({note})")

    print()
    print("-- opacity --")
    for source, expected, note in OPAQUE_CASES:
        got = shell_ast.opaque_head(source)
        ok = got == expected
        if not ok:
            failures.append(f"opaque {source!r}: want {expected!r} got {got!r}")
        print(f"  {'ok  ' if ok else 'FAIL'} {source:34} -> {got!r}   ({note})")

    print()
    print("-- parse verdict --")
    for source, expected, note in PARSE_CASES:
        got = shell_ast.parse_ok(source)
        ok = got is expected
        if not ok:
            failures.append(f"parse {source!r}: want {expected} got {got}")
        print(f"  {'ok  ' if ok else 'FAIL'} {source!r:32} -> {got}   ({note})")

    print()
    print("-- degraded import (grammar hidden) --")
    ok, detail = _run_isolated_import_check()
    if not ok:
        failures.append(f"degraded import failed: {detail}")
    print(f"  {'ok  ' if ok else 'FAIL'} {detail}")

    print()
    print(f"failures={len(failures)}")
    for failure in failures:
        print(f"  FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
