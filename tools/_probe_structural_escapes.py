"""Probe: structural shell constructs must not hide a destructive command.

Read-only. Exit 0 only if every case is graded as expected.

Why this exists (2026-09-08): the grading engine used to scan the raw command
text with regular expressions. A regex sees characters, not structure, so a
destructive command nested inside shell syntax was invisible whenever the
opening token was not a separator:

    (rm -rf /)                      subshell
    { rm -rf /; }                   compound statement
    ! rm -rf /                      negation
    FOO=bar rm -rf /                variable-assignment prefix
    if ...; then rm -rf /; fi       control flow
    f() { rm -rf /; }; f            function body

Measured before the fix: 13 of 20 structural commands escaped as LOW. The fix
is to walk a real syntax tree (tree-sitter-bash) and grade every `command` node
found anywhere in it, instead of pattern-matching the text.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qoder_guard.risk import RiskLevel, assess  # noqa: E402


# (command, expected level, description)
CASES: list[tuple[str, RiskLevel, str]] = [
    # -- structure that used to escape ------------------------------------
    ("(rm -rf /)", RiskLevel.HIGH, "subshell"),
    ("(rm -rf /tmp/x)", RiskLevel.HIGH, "subshell with a real target"),
    ("{ rm -rf /; }", RiskLevel.HIGH, "compound statement"),
    ("! rm -rf /", RiskLevel.HIGH, "negated command"),
    ("FOO=bar rm -rf /", RiskLevel.HIGH, "variable-assignment prefix"),
    ("FOO=bar BAZ=qux rm -rf /", RiskLevel.HIGH, "two assignment prefixes"),
    ("if true; then rm -rf /; fi", RiskLevel.HIGH, "if body"),
    ("if false; then true; else rm -rf /; fi", RiskLevel.HIGH, "else body"),
    ("for f in *; do rm -rf $f; done", RiskLevel.HIGH, "for body"),
    ("while true; do rm -rf /; done", RiskLevel.HIGH, "while body"),
    ("until false; do rm -rf /; done", RiskLevel.HIGH, "until body"),
    ("case x in x) rm -rf /;; esac", RiskLevel.HIGH, "case item"),
    ("f() { rm -rf /; }; f", RiskLevel.HIGH, "function body"),
    ("sudo (rm -rf /)", RiskLevel.HIGH, "subshell as sudo argument"),
    ("( ( rm -rf / ) )", RiskLevel.HIGH, "nested subshells"),
    ("echo hi > /dev/null; (rm -rf /)", RiskLevel.HIGH, "subshell after redirect"),
    # -- nesting inside another command -----------------------------------
    ("echo $(rm -rf /)", RiskLevel.HIGH, "command substitution"),
    ("echo `rm -rf /`", RiskLevel.HIGH, "backtick substitution"),
    ("true | rm -rf /", RiskLevel.HIGH, "pipeline right side"),
    ("[ -d / ] && rm -rf /", RiskLevel.HIGH, "test chain"),
    ("time rm -rf /", RiskLevel.HIGH, "time wrapper"),
    ("nohup rm -rf / &", RiskLevel.HIGH, "background"),
    # -- benign structural commands must NOT become high ------------------
    ("(ls -la)", RiskLevel.LOW, "benign subshell"),
    ("{ echo hi; }", RiskLevel.LOW, "benign compound statement"),
    ("! true", RiskLevel.LOW, "benign negation"),
    ("FOO=bar echo hi", RiskLevel.LOW, "assignment prefix on a read-only head"),
    ("if true; then echo hi; fi", RiskLevel.LOW, "benign if body"),
    ("for f in *; do echo $f; done", RiskLevel.LOW, "benign for body"),
    ("f() { echo hi; }; f", RiskLevel.LOW, "benign function body"),
    ("case x in x) echo hi;; esac", RiskLevel.LOW, "benign case item"),
    ("rm -rf /tmp/build", RiskLevel.HIGH, "plain rm still graded high"),
    ("rm /tmp/build", RiskLevel.MEDIUM, "plain rm without force is medium"),
]


def main() -> int:
    failures: list[str] = []
    print(f"{'command':42} {'want':8} {'got':8} note")
    print("-" * 110)
    for command, want, note in CASES:
        level, reason = assess("Bash", {"command": command})
        ok = level is want
        if not ok:
            failures.append(f"{command!r} want {want.value} got {level.value}: {reason}")
        print(f"{command:42} {want.value:8} {level.value:8} {note}"
              + ("" if ok else "   <-- MISMATCH"))

    print()
    print(f"cases={len(CASES)}  failures={len(failures)}")
    for failure in failures:
        print(f"  FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
