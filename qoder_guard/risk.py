"""Risk assessment engine (stage A skeleton).

Holds a table of dangerous command patterns and grades every tool call:

  RiskLevel:
    LOW     read-only / safe (git status, ls, cat, grep ...)
    MEDIUM  normal operations with side effects (file writes, git add/commit ...)
    HIGH    high risk (deletion, force push, recursive chmod, download-and-run ...)

Stage A: results only go to the audit log so the false-positive rate can be
         reviewed afterwards.
Stage B: HIGH/MEDIUM grades feed the hook decision -- HIGH is blocked, MEDIUM
         follows the permission tier, LOW passes through.

Note: the rule table is only a first coarse filter, not the sole basis. Real
impact analysis ("this command will delete 12 files") is added in stage B via
dry-run style pre-analysis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .shell_tokens import (
    SEPARATORS,
    TokenizedCommand,
    command_heads,
    has_opaque,
    has_opaque_head,
    tokenize,
)

# Structural parsing is an OPTIONAL capability, deliberately isolated: if the
# grammar is missing (venv deleted and uv unavailable) the guard must keep
# working in regex-only mode rather than crash the hook.
try:  # pragma: no cover - exercised by tools/_probe_shell_ast.py
    from . import shell_ast
    _SHELL_AST_AVAILABLE = shell_ast.AVAILABLE
    if not _SHELL_AST_AVAILABLE:  # pragma: no cover
        shell_ast = None  # type: ignore[assignment]
except ImportError:  # pragma: no cover - module absent
    shell_ast = None  # type: ignore[assignment]
    _SHELL_AST_AVAILABLE = False


# Ordering for "take the highest level". UNKNOWN gets no value -- it does not
# take part in the "which is more dangerous" comparison; the policy layer
# handles it separately (see policy.AskRisky).
# Keyed by the string value so it can be defined before the enum.
_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


class RiskLevel(str, Enum):
    # UNKNOWN covers "cannot be statically evaluated" (variable expansion,
    # parse failure, ...). It does not mean "no risk" but "cannot tell" -- the
    # policy layer should act conservatively (see policy.AskRisky).
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    # Because RiskLevel subclasses `str`, the inherited string ordering applies
    # silently and alphabetically (HIGH < LOW < MEDIUM), so `max()` over a list
    # of levels would return MEDIUM for {low, medium, high}. These explicit
    # operators restore severity ordering and make UNKNOWN unrankable by raising
    # ValueError, which is the same contract OpenHands software-agent-sdk (MIT)
    # uses -- see THIRD_PARTY_LICENSES.md. Ported rather than hand-rolled
    # because the original UNKNOWN-as-HIGH bug came from ad-hoc ordering.
    def _order_key(self, other: object) -> int | None:
        """Return other's severity rank, or None when other is not a level."""
        if not isinstance(other, RiskLevel):
            return None
        if self is RiskLevel.UNKNOWN or other is RiskLevel.UNKNOWN:
            raise ValueError("Cannot compare unknown risk levels.")
        return _ORDER[other]

    def __lt__(self, other: object) -> bool:
        key = self._order_key(other)
        if key is None:
            return NotImplemented
        return _ORDER[self] < key

    def __gt__(self, other: object) -> bool:
        key = self._order_key(other)
        if key is None:
            return NotImplemented
        return _ORDER[self] > key

    def __le__(self, other: object) -> bool:
        key = self._order_key(other)
        if key is None:
            return NotImplemented
        return _ORDER[self] <= key

    def __ge__(self, other: object) -> bool:
        key = self._order_key(other)
        if key is None:
            return NotImplemented
        return _ORDER[self] >= key


@dataclass(frozen=True)
class Rule:
    level: RiskLevel
    pattern: re.Pattern
    reason: str

# Operators that start a new gradable command. `&&`/`||` are matched before the
# single-char alternatives so the split never leaves a stray `&`.
_SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||;|&|\|")


# Dangerous command patterns: a hit means high risk. Deliberately conservative
# -- prefer a false block over a missed dangerous command.
_HIGH_RULES: list[Rule] = [
    # `rm` is NOT graded here: presence alone says nothing, only the flag shape
    # does. See _grade_rm_shape.
    Rule(RiskLevel.HIGH, re.compile(r"\brmdir\b", re.I), "directory removal"),
    Rule(RiskLevel.HIGH, re.compile(r"\b(git\s+)?push\s+.*--force", re.I), "force push"),
    Rule(RiskLevel.HIGH, re.compile(r"\b(git\s+)?reset\s+--hard", re.I), "hard reset of worktree"),
    # chmod is NOT graded here: only a world-writable/setuid mode is an
    # escalation, and the mode must be read positionally. See _grade_chmod_shape.
    Rule(RiskLevel.HIGH, re.compile(r"\bchown\s+-R", re.I), "recursive ownership change"),
    Rule(RiskLevel.HIGH, re.compile(r"\bmkfs|format\s+[a-z]:", re.I), "disk format"),
    Rule(RiskLevel.HIGH, re.compile(r"\b(curl|wget)\b.*\|\s*(?:sudo\s+)?(?:[\w./\\-]*/)?(?:ba|z|da|k)?sh\b", re.I), "download and execute"),
    Rule(RiskLevel.HIGH, re.compile(r"\bdd\b[^;|&]*\bof=\s*/dev/(?:sd|hd|nvme|vd|disk|mmcblk)", re.I), "raw disk write"),
    # `shred` is destructive only as a COMMAND, and only with a target. A plain
    # `\bshred\b` search also matched prose (`git commit -m "shred the
    # evidence"`) and the bare word; anchoring on a command position plus one
    # non-flag operand keeps the real invocation and drops the rest.
    Rule(RiskLevel.HIGH, re.compile(
        r"(?:^|[;&|])\s*"
        r"(?:(?:sudo|command|env|nohup|nice|time|exec|builtin)\s+)*"
        r"(?:[\w./\\-]*[/\\])?shred\b(?:\s+-{1,2}[a-z-]+)*\s+[^\s-]",
        re.I), "irrecoverable file destruction"),
    Rule(RiskLevel.HIGH, re.compile(r"\bfind\b[^;|&]*-delete\b", re.I), "bulk delete via find"),
    Rule(RiskLevel.HIGH, re.compile(r">>?\s*/dev/(?:sd|hd|nvme|vd|disk|mmcblk)", re.I), "raw device write"),
    Rule(RiskLevel.HIGH, re.compile(r"\b(reg\s+delete|del\s+/[a-z]*[fq]|Remove-Item\s+-Recurse)", re.I), "registry/file force delete"),
    Rule(RiskLevel.HIGH, re.compile(r"\bdiskpart\b", re.I), "disk partitioning"),
    Rule(RiskLevel.HIGH, re.compile(r"\bformat\b", re.I), "formatting"),
]

# A redirect that actually writes: `>`/`>>` followed by a non-empty target.
# The lookbehind keeps file-descriptor redirects (`2>&1`) and non-redirect uses
# (`a=>b`, `a -> b`) from being mistaken for a write. No whitespace is required
# before `>`, otherwise `echo hi>out.txt` would slip past.
_WRITE_REDIRECT_RE = re.compile(r"(?<![0-9>=-])(>>?)\s*[^\s>|&;=]+")

_MEDIUM_RULES: list[Rule] = [
    Rule(RiskLevel.MEDIUM, re.compile(r"\b(git\s+)?push\b", re.I), "push"),
    Rule(RiskLevel.MEDIUM, re.compile(r"\b(git\s+)?checkout\s+-b|\bgit\s+switch", re.I), "branch switch/create"),
    Rule(RiskLevel.MEDIUM, re.compile(r"\bgit\s+merge\b|\bgit\s+rebase\b|\bgit\s+cherry-pick\b", re.I), "merge/rebase/cherry-pick"),
    Rule(RiskLevel.MEDIUM, re.compile(r"\bgit\s+clean\b", re.I), "clean untracked files"),
    Rule(RiskLevel.MEDIUM, re.compile(r"\b(pip|npm|nuget)\s+install\b|\bapt(-get)?\s+(install|remove|purge)", re.I), "dependency install/remove"),
    Rule(RiskLevel.MEDIUM, re.compile(r"\b(mv|Move-Item|rename)\b", re.I), "move/rename"),
    Rule(RiskLevel.MEDIUM, re.compile(r"\b(cp|Copy-Item)\s+-[a-zA-Z]*r", re.I), "recursive copy"),
    # Redirect to file: requires > followed by a non-empty target that is not a
    # comparison (as in [ -f x ] or a > b).
    Rule(RiskLevel.MEDIUM, _WRITE_REDIRECT_RE, "write/append output to file"),
    Rule(RiskLevel.MEDIUM, re.compile(r"\b(taskkill|Stop-Process|kill)\b", re.I), "terminate process"),
]

# Explicit read-only/safe allow patterns: a hit means LOW. Checked before the
# HIGH rules, so the whitelist wins -- but see _grade_line: it is SKIPPED when
# the segment writes via a redirect, otherwise `echo hi > out.txt` is excused by
# its `echo` head and graded LOW despite writing a file.
_LOW_RULES: list[Rule] = [
    Rule(RiskLevel.LOW, re.compile(r"^(ls|dir|cat|type|head|tail|less|more|pwd|echo|whoami)\b", re.I), "read-only command"),
    Rule(RiskLevel.LOW, re.compile(r"^(git\s+)?(status|log|diff|show|branch|remote|fetch|grep)\b", re.I), "read-only git"),
    Rule(RiskLevel.LOW, re.compile(r"^(Get-ChildItem|Get-Content|Get-Location|Get-Process)\b", re.I), "read-only PowerShell"),
    # `[` / `test` only compares; without this they fall through to the
    # opaque-head path (`[` holds a shell meta character) and grade UNKNOWN.
    Rule(RiskLevel.LOW, re.compile(r"^(test\b|\[)", re.I), "shell test/comparison"),
]


# -- Deletion family -------------------------------------------------------
# `rm` is graded by SHAPE, not by presence: only recursive AND force together
# is the destructive shape. OpenHands software-agent-sdk (MIT) pins the same
# rule (`rm -rf /` -> HIGH, `rm "-r" file` -> not the destructive shape) -- see
# THIRD_PARTY_LICENSES.md.
#
# Regression this replaces: the old rule made the flag group OPTIONAL
# (`\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)?.*`), so EVERY `rm` invocation graded
# HIGH. Audit evidence (803 records, 2026-09-08): `rm -rf /tmp` -> high was
# correct, but `rm file.txt` also graded high, i.e. ordinary file deletes were
# blocked. A plain delete is the same impact class as `mv` / `cp -r` /
# `git clean`, which the existing table already grades MEDIUM.
# `rm` is only a delete when it is the COMMAND. Anchoring on a command position
# keeps operands such as `wc -l rm.txt` or `python rm.py` out of the match.
# Command WRAPPERS (`sudo`, `command`, `env`, `nohup`, ...) and PATH PREFIXES
# (`/bin/rm`, `./rm`) are skipped, because `command rm -rf /` deletes exactly
# what `rm -rf /` deletes -- both escaped before this was added.
_RM_WRAPPERS = r"(?:(?:sudo|command|env|nohup|nice|time|exec|builtin)\s+)*"
_RM_INVOCATION_RE = re.compile(
    r"(?:^|[;&|])\s*" + _RM_WRAPPERS + r"(?:[\w./\\-]*[/\\])?rm\b(?P<args>[^;|&]*)",
    re.I,
)
_SHORT_FLAG_RE = re.compile(r"^-([A-Za-z]+)$")
_LONG_FLAG_RE = re.compile(r"^--[a-z][a-z-]*$")

# Shell runners execute a script passed as an argument, so the script body is
# itself a command that must be graded -- otherwise `bash -c 'rm -rf /'` is
# excused by the `bash` head. Same for `eval` and for `xargs`.
_RUNNER_SCRIPT_RE = re.compile(
    r"\b(?:ba|z|da|k)?sh\s+(?:-[A-Za-z]*c[A-Za-z]*\s+)?"
    r"(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
)
_EVAL_RE = re.compile(r"\beval\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))")
_XARGS_RE = re.compile(r"(?:^|[;&|])\s*xargs\b(?P<args>.*)")
_FIND_EXEC_RE = re.compile(r"-exec\s+(?P<cmd>[^-].*?)(?:\s*[;+]|$)")

# Opaque code execution: the guard cannot read what the string does, so the
# presence of a destructive verb inside it is the only signal available.
_CODE_EXEC_RE = re.compile(
    r"\b(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output)|"
    r"shutil\.rmtree|child_process\.exec|Function)\s*\(",
    re.I,
)
# Interpreters invoked with an inline program (`perl -e '...'`). The program is
# opaque, so only a destructive verb inside it can be seen.
_CODE_INLINE_RE = re.compile(
    r"\b(?:python3?|perl|ruby|node|php)\b[^;|&]*\s-[ce]\b", re.I
)
_CODE_DESTRUCTIVE_RE = re.compile(
    r"\brm\b\W{0,4}-[a-z]*r|rmtree|mkfs|dd\s+if=|shred|chmod\s+(-R\s+)?[0-7]{3,4}",
    re.I,
)

# chmod is graded by MODE, not by presence: `chmod 644 file` is routine, only a
# world-writable or setuid/setgid mode is an escalation. The old rule matched
# every numeric mode, so ordinary permission fixes graded HIGH.
_CHMOD_INVOCATION_RE = re.compile(
    r"(?:^|[;&|])\s*" + _RM_WRAPPERS + r"(?:[\w./\\-]*[/\\])?chmod\s+(?P<args>[^;|&]*)",
    re.I,
)
# World-writable / world-write "other" digit, or a setuid/setgid leading digit.
_CHMOD_DANGEROUS_MODE_RE = re.compile(r"^(?:[0-7]?[0-7][0-7][67]|[246][0-7]{3})$")
_CHMOD_RECURSIVE_RE = re.compile(r"^(?:-R|-r|--recursive)$", re.I)


_DESTRUCTIVE_SHORT_FLAG_RE = re.compile(r"(?<!\S)-([A-Za-z]+)(?!\S)")
_DESTRUCTIVE_LONG_FLAG_RE = re.compile(r"(?<!\S)--[a-z][a-z-]*(?!\S)", re.I)


def _has_destructive_flag_shape(text: str) -> bool:
    """Whether `text` carries recursive AND force flags somewhere.

    Only used when the command verb could not be resolved: the destructive
    shape is then real but we cannot tell which program receives it. Long and
    short forms are checked separately because the long forms may appear in
    either order.
    """
    for letters in _DESTRUCTIVE_SHORT_FLAG_RE.findall(text):
        if ("r" in letters or "R" in letters) and "f" in letters:
            return True
    lowered = {f.lower() for f in _DESTRUCTIVE_LONG_FLAG_RE.findall(text)}
    return "--recursive" in lowered and "--force" in lowered


def _grade_chmod_shape(line: str) -> tuple[RiskLevel, str] | None:
    """Grade `chmod` by its mode. None = no chmod, or a routine mode.

    A world-writable/setuid mode is HIGH; a recursive symbolic change is
    MEDIUM (a side effect); `chmod 644 file` is routine and returns None so the
    normal rule flow decides (LOW).
    """
    match = _CHMOD_INVOCATION_RE.search(line)
    if match is None:
        return None
    recursive = False
    mode: str | None = None
    for word in match.group("args").split():
        if _CHMOD_RECURSIVE_RE.match(word):
            recursive = True
            continue
        if word.startswith("-"):
            continue
        if mode is None:
            mode = word
    if mode is not None and _CHMOD_DANGEROUS_MODE_RE.match(mode):
        return (RiskLevel.HIGH,
                f"permission escalation (world-writable/setuid mode {mode})"
                f" (rule matched: {line[:80]})")
    if recursive:
        return (RiskLevel.MEDIUM,
                f"recursive permission change (rule matched: {line[:80]})")
    return None


def _is_benign_code_exec(line: str) -> bool:
    """Whether `line` is an opaque code-exec primitive with NO destructive verb.

    Such a segment is already graded MEDIUM by _grade_code_exec. It is kept
    distinct because the opaque-argument escalation in assess() would otherwise
    raise it to HIGH: `subprocess.run(['ls'])` has an unresolvable argument list
    but runs nothing destructive, and escalating it blocked ordinary build code.
    """
    if not (_CODE_EXEC_RE.search(line) or _CODE_INLINE_RE.search(line)):
        return False
    return not _CODE_DESTRUCTIVE_RE.search(line)


def _grade_code_exec(line: str) -> tuple[RiskLevel, str] | None:
    """Grade opaque code execution (`python -c "...os.system('rm -rf /')"`).

    The guard cannot read the code, so it falls back to the only available
    signal: a destructive verb inside the string. A bare `subprocess.run(` with
    no destructive verb is MEDIUM rather than HIGH, because that primitive is
    common in legitimate scripts.
    """
    if not (_CODE_EXEC_RE.search(line) or _CODE_INLINE_RE.search(line)):
        return None
    if _CODE_DESTRUCTIVE_RE.search(line):
        return (RiskLevel.HIGH,
                f"destructive operation inside an opaque code string (rule matched: {line[:80]})")
    return (RiskLevel.MEDIUM,
            f"opaque code execution primitive; contents cannot be inspected (rule matched: {line[:80]})")


def _strip_leading_flags(text: str) -> str:
    """Drop leading option words so a wrapped command becomes gradable.

    `xargs -0 rm -rf /` and `xargs -I{} rm -rf {}` hide the real command behind
    xargs options; without this they never reach the `rm` shape check.
    """
    words = text.split()
    index = 0
    while index < len(words) and words[index].startswith("-"):
        index += 1
    return " ".join(words[index:])


def _grade_shell_runners(text: str, depth: int = 0) -> tuple[RiskLevel, str] | None:
    """Grade commands hidden inside a shell runner, `eval`, `xargs` or find.

    `bash -c 'rm -rf /'` and `eval 'rm -rf /'` run exactly what `rm -rf /`
    runs, but the outer head is a harmless-looking `bash`/`eval`, so the rule
    table never sees the delete. The script body is graded as a command.
    """
    if depth >= 3:
        return None
    best: tuple[RiskLevel, str] | None = None
    for regex in (_RUNNER_SCRIPT_RE, _EVAL_RE):
        for m in regex.finditer(text):
            body = (m.group(1) or m.group(2) or m.group(3) or "").strip()
            if not body:
                continue
            best = _keep_higher(best, _grade_lines(body))
            best = _keep_higher(best, _grade_shell_runners(body, depth + 1))
    for m in _XARGS_RE.finditer(text):
        args = _strip_leading_flags(m.group("args").strip())
        if args:
            best = _keep_higher(best, _grade_lines(args))
    for m in _FIND_EXEC_RE.finditer(text):
        args = m.group("cmd").strip()
        if args:
            best = _keep_higher(best, _grade_lines(args))
    return best


def _grade_rm_shape(line: str) -> tuple[RiskLevel, str] | None:
    """Grade an `rm` invocation by its flag shape. None = no `rm` found.

    recursive AND force together -> HIGH (the destructive shape)
    anything else                -> MEDIUM (a delete, but a bounded one)

    A flag word that only exists after expansion (`rm -r "$FLAGS" /`) is
    unknown, not hostile: flagging it would make every `$OPTS` invocation
    destructive, so only the flags actually visible are counted.
    """
    match = _RM_INVOCATION_RE.search(line)
    if match is None:
        return None
    recursive = force = False
    for word in match.group("args").split():
        if word == "--":
            break  # everything after `--` is an operand, never a flag
        if _LONG_FLAG_RE.match(word):
            if word == "--recursive":
                recursive = True
            elif word == "--force":
                force = True
            continue
        short = _SHORT_FLAG_RE.match(word)
        if short:
            letters = short.group(1)
            if "r" in letters or "R" in letters:
                recursive = True
            if "f" in letters:
                force = True
    if recursive and force:
        return (RiskLevel.HIGH,
                f"recursive force delete (rule matched: {line[:80]})")
    missing = "force flag" if recursive else "recursive flag"
    return (RiskLevel.MEDIUM,
            f"file delete without the recursive+force shape (no {missing})"
            f" (rule matched: {line[:80]})")


def assess(tool_name: str, tool_input) -> tuple[RiskLevel, str]:
    """Assess the risk of a single tool call.

    Returns (risk level, reason). For non-Bash tools the tool's read/write
    nature is used as a coarse guess.
    """
    name = (tool_name or "").lower()

    # 1) Decide by tool name first: read-only tools (Read/Glob/Grep...) are
    #    always low risk; file-writing tools (Write/Edit...) are medium (stage B
    #    adds impact analysis). This must run before text parsing -- otherwise
    #    Read's file_path argument would be misread as medium.
    if name in ("read", "glob", "grep", "list", "websearch", "webfetch",
                "directory", "view", "ls", "todolist", "tasklist", "taskget"):
        return RiskLevel.LOW, f"tool {tool_name} is read-only"
    if name in ("write", "edit", "multiedit", "patch", "apply_diff",
                "notebookedit"):
        return RiskLevel.MEDIUM, f"tool {tool_name} modifies files; impact analysis pending"
    # Monitor carries command execution in practice (its argument is `command`),
    # so it falls through to the command text parsing below.
    # Agent / Task spawn sub-agents whose own tool calls trigger their own hooks,
    # so they are only recorded as medium here to avoid double counting.
    if name in ("agent", "task", "taskcreate"):
        return RiskLevel.MEDIUM, f"tool {tool_name} spawns/dispatches subtasks"

    text = ""
    if isinstance(tool_input, str):
        text = tool_input
    elif isinstance(tool_input, dict):
        # Argument names differ per tool: command/description/params ... pick
        # whichever looks most like command text.
        text = " ".join(
            str(v) for k, v in tool_input.items()
            if k.lower() in ("command", "description", "params", "query",
                             "input", "code", "content")
        )
    text = text.strip()

    # Unknown tool with no analyzable text: do not jump to high risk, treat as
    # medium (record rather than over-block).
    if not text:
        return RiskLevel.MEDIUM, "unrecognized tool with no argument text; treated as medium"

    # 2) Normalize via static tokenization: strip quotes before matching rules
    #    so quote tricks like "rm" / r""m cannot slip through.
    tc = tokenize(text)
    if not tc.parse_ok:
        # A parse failure is NOT itself a risk: arbitrary non-shell text fails
        # to parse all the time (`echo "unclosed`), and routing every such
        # string to the review queue floods it. Grade the RAW text instead --
        # quotes are not stripped, so any destructive shape stays visible --
        # and only surface a level when a real shape is there.
        level, reason = _grade_lines(text)
        sub = _grade_substitutions(text)
        if sub is not None:
            level, reason = _keep_higher((level, reason), sub)
        if level is RiskLevel.HIGH or level is RiskLevel.MEDIUM:
            return level, f"unparseable command, graded from raw text: {reason}"
        # The destructive flag SHAPE is visible even when the verb is not:
        # `foo -rf / "unclosed` carries recursive+force but we cannot tell what
        # program receives it, so the shape must not be dismissed as LOW.
        # OpenHands software-agent-sdk (MIT) reports the same case as uncertain.
        if _has_destructive_flag_shape(text):
            return RiskLevel.UNKNOWN, (
                "unparseable command carries a recursive+force flag shape on an "
                "unresolvable verb; needs manual review"
            )
        # No shape found, but runtime values are present: we cannot tell what
        # they expand to, and the parse failure means we could not even locate
        # the command name. Stay conservative instead of claiming LOW.
        if "$" in text or "`" in text:
            return RiskLevel.UNKNOWN, (
                "command cannot be parsed statically and contains runtime values; "
                "needs manual review"
            )
        return RiskLevel.LOW, (
            f"unparseable command with no risk shape; treated as low: {reason}"
        )

    # 3) Opacity handling -- two very different cases (see shell_tokens.command_heads):
    #
    #    (a) an opaque COMMAND NAME (`x=rm; $x -rf /`) -> truly undecidable,
    #        because we cannot tell which program runs.
    #    (b) opacity only in the ARGUMENTS (`echo $HOME`) -> the command name is
    #        still known, so grading by that name remains meaningful; the unknown
    #        argument only means the *target* is unknown, not the operation.
    #
    #    Real audit data (2026-09-08, 381 records): 8 UNKNOWN, of which 6 were
    #    `x=rm; $x -rf /` (case a) and 2 were harmless/gradeable (case b,
    #    e.g. `echo $HOME`). Treating all 8 alike would block harmless commands.
    if has_opaque_head(tc):
        opaque_heads = [t.text for t in command_heads(tc) if t.opaque][:3]
        return RiskLevel.UNKNOWN, (
            f"command name cannot be resolved statically: {' '.join(opaque_heads)}"
        )
    # A command substitution body is itself a command that will run. Grade it
    # before the opaque-argument path, which only sees the head and would grade
    # `cat `rm -rf /tmp`` as read-only.
    sub = _grade_substitutions(tc.raw)
    if sub is not None and sub[0] is RiskLevel.HIGH:
        return sub
    runner = _grade_shell_runners(tc.raw)
    if runner is not None and runner[0] is RiskLevel.HIGH:
        return runner
    if has_opaque(tc):
        # A nested command can be fully resolvable even when the OUTER command
        # carries runtime values: `for f in *; do rm -rf $f; done` has an opaque
        # loop variable and glob, yet the `rm -rf` inside is plain. The head-only
        # path below only sees `for` and would grade LOW, so consult the syntax
        # tree first.
        nested = _grade_ast_commands(tc.raw)
        if nested is not None and nested[0] is RiskLevel.HIGH:
            return nested
        opaque_args = [t.text for t in tc.tokens if t.opaque][:3]
        # Grade on the command name; arguments carry runtime values, so escalate
        # one notch (a known-dangerous command with an unknown target is worse
        # than a plain match -- we cannot verify the target is safe).
        level, reason = _grade_by_name(tc)
        if level is RiskLevel.HIGH:
            return level, f"{reason}; target has runtime values: {' '.join(opaque_args)}"
        # The deletion family is graded by SHAPE (recursive+force), and the
        # shape is a property of the flags we can SEE. An opaque flag word
        # (`rm -r "$FLAGS" /`) or an opaque target cannot create the
        # destructive shape, so escalating it to HIGH would block ordinary
        # deletes whose paths happen to be variables.
        if _RM_INVOCATION_RE.search(tc.raw):
            return level, f"{reason}; arguments have runtime values: {' '.join(opaque_args)}"
        # A write redirect still writes even when the head is read-only:
        # `echo x > ~/.ssh/authorized_keys` has an opaque target, so the head
        # alone would grade LOW. The redirect is the reason it is not read-only.
        if _WRITE_REDIRECT_RE.search(tc.raw):
            return RiskLevel.MEDIUM, (
                f"{reason}; command writes output to a file, target has runtime "
                f"values: {' '.join(opaque_args)}"
            )
        # An opaque code-exec primitive without a destructive verb is already
        # MEDIUM by its own rule. Escalating it to HIGH here was a false
        # positive: `subprocess.run(['ls'])` has an unresolvable argument list
        # yet performs no destructive operation.
        if _is_benign_code_exec(tc.raw):
            return level, (
                f"{reason}; argument has runtime values: {' '.join(opaque_args)}"
            )
        if level is RiskLevel.MEDIUM:
            return RiskLevel.HIGH, (
                f"{reason}; target has runtime values, cannot verify it is safe: "
                f"{' '.join(opaque_args)}"
            )
        # LOW: a read-only command with a runtime argument (e.g. `echo $HOME`)
        return level, f"{reason}; argument has runtime values: {' '.join(opaque_args)}"

    # 4) Rebuild text from quote-stripped tokens before matching rules
    text = " ".join(t.text for t in tc.tokens)
    return _grade_lines(text)


def _split_segments(text: str) -> list[str]:
    """Split a command into independently-gradable segments.

    Every operator that lets a following command run must start a new segment,
    otherwise the trailing command is excused by the leading read-only one:

        `echo hi || rm -rf /`   the rm runs when echo fails -- must be graded
        `pwd | xargs rm -rf`    the rm runs as the pipeline's right side
        `echo hi & rm -rf /`    the rm runs in the background
        `echo hi && rm -rf /`   runs on success
        `echo hi ; rm -rf /`    runs unconditionally

    Regression (found in debug): the old implementation only replaced `;` and
    `&&`, so `||`, `|` and `&` left the dangerous part inside the first segment,
    where the read-only whitelist swallowed it (`echo hi || rm -rf /` -> LOW).

    `>`, `>>` and `<` are deliberately NOT separators: the redirect rule needs
    them intact (`echo hi > f`).
    """
    out: list[str] = []
    for part in _SEGMENT_SPLIT_RE.split(text):
        part = part.strip()
        if part:
            out.append(part)
    return out


def _grade_line(line: str) -> tuple[RiskLevel, str] | None:
    """Grade a single segment: read-only whitelist first, then high, then medium.

    The whitelist is skipped when the segment writes through a redirect. A
    read-only head says nothing about the whole command: `echo hi > out.txt`
    only reads its arguments but overwrites a file, and `echo x >
    ~/.ssh/authorized_keys` overwrites an auth file. Letting the whitelist win
    graded those LOW, i.e. the guard layer granted more permission than the
    command deserved. Skipping it lets the MEDIUM redirect rule fire.
    """
    if not _WRITE_REDIRECT_RE.search(line):
        for rule in _LOW_RULES:
            if rule.pattern.match(line):
                return (rule.level, rule.reason)
    rm_shape = _grade_rm_shape(line)
    if rm_shape is not None:
        return rm_shape
    chmod_shape = _grade_chmod_shape(line)
    if chmod_shape is not None:
        return chmod_shape
    code_exec = _grade_code_exec(line)
    if code_exec is not None:
        return code_exec
    for rule in _HIGH_RULES:
        if rule.pattern.search(line):
            return (rule.level, f"{rule.reason} (rule matched: {line[:80]})")
    for rule in _MEDIUM_RULES:
        if rule.pattern.search(line):
            return (rule.level, rule.reason)
    return None


def _keep_higher(best: tuple[RiskLevel, str] | None,
                 hit: tuple[RiskLevel, str] | None) -> tuple[RiskLevel, str] | None:
    """Keep whichever verdict ranks higher (UNKNOWN never wins a comparison)."""
    if hit is None:
        return best
    if best is None:
        return hit
    return hit if _ORDER[hit[0].value] > _ORDER[best[0].value] else best


def _canonical_command(command: object) -> str:
    """Rebuild a command's text from its parsed name and words.

    The raw node text keeps the leading variable assignments
    (`FOO=bar rm -rf /`), which hides `rm` from every rule that anchors on a
    segment start. Rebuilding as `rm -rf /` makes the delete visible again.
    """
    name = getattr(command, "name", None)
    if not name:
        return str(getattr(command, "text", "")).strip()
    words = getattr(command, "words", ())
    return " ".join([str(name), *[str(word) for word in words]]).strip()


def _grade_ast_commands(text: str, depth: int = 0) -> tuple[RiskLevel, str] | None:
    """Grade every command the syntax tree exposes, including nested ones.

    A regex over raw text sees characters, not structure, so a destructive
    command nested in shell syntax was invisible whenever the opening token was
    not a separator. Measured 2026-09-08: 13 of 20 structural commands graded
    LOW, e.g. `(rm -rf /)`, `! rm -rf /`, `FOO=bar rm -rf /`,
    `if true; then rm -rf /; fi`, `f() { rm -rf /; }; f`.

    The syntax tree gives every `command` node, so each one is graded on its
    own canonical text. The node equal to the whole input is skipped: the
    caller already graded that text, and re-grading it would recurse without
    end.
    """
    if depth >= 2 or shell_ast is None or not _SHELL_AST_AVAILABLE:
        return None
    best: tuple[RiskLevel, str] | None = None
    target = text.strip()
    for command in shell_ast.iter_commands(text):
        for candidate in (_canonical_command(command), str(getattr(command, "text", "")).strip()):
            if not candidate or candidate == target:
                continue
            best = _keep_higher(best, _grade_line(candidate))
            best = _keep_higher(best, _grade_ast_commands(candidate, depth + 1))
    return best


def _grade_lines(text: str) -> tuple[RiskLevel, str]:
    """Grade the whole command and every segment, keeping the highest level.

    Three passes are required:
      - the WHOLE text catches cross-segment patterns (`curl ... | sh`), which
        would be invisible after splitting;
      - the SYNTAX TREE catches commands nested in structure (subshell, if/for/
        case, function body), which no text pattern can locate;
      - each SEGMENT catches a dangerous command hidden behind a read-only
        prefix (`echo hi || rm -rf /`), which the whole-text whitelist would
        swallow because `_LOW_RULES` uses `.match()` on the first word.
    """
    best = _grade_line(text)
    if best is not None and best[0] is RiskLevel.HIGH:
        return best
    best = _keep_higher(best, _grade_ast_commands(text))
    if best is not None and best[0] is RiskLevel.HIGH:
        return best
    for line in _split_segments(text):
        if line == text:
            continue
        best = _keep_higher(best, _grade_line(line))
        if best is not None and best[0] is RiskLevel.HIGH:
            break  # already the highest level, no need to keep scanning
    return best if best is not None else (RiskLevel.LOW, "no risk rule matched")


# Command substitutions: `$(...)` and backticks. The body is a command that
# runs, so it must be graded -- otherwise a read-only head excuses it.
_SUBSTITUTION_RE = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def _grade_substitutions(text: str, depth: int = 0) -> tuple[RiskLevel, str] | None:
    """Grade the commands inside command substitutions, recursively.

    `echo $(whoami)` runs `whoami`; ``cat `rm -rf /tmp` `` runs `rm -rf /tmp`.
    Both have a resolvable read-only head, so the opacity path only marked the
    argument as a runtime value and graded by the head -- LOW for both, which
    under-graded the second one. Nested bodies are walked up to a small depth.
    """
    if depth >= 3:
        return None
    best: tuple[RiskLevel, str] | None = None
    for m in _SUBSTITUTION_RE.finditer(text):
        inner = (m.group(1) or m.group(2) or "").strip()
        if not inner:
            continue
        best = _keep_higher(best, _grade_lines(inner))
        best = _keep_higher(best, _grade_substitutions(inner, depth + 1))
    return best


def _grade_by_name(tc: TokenizedCommand) -> tuple[RiskLevel, str]:
    """Grade a command whose arguments are opaque, using its command names.

    Only the resolvable parts are matched, so a known command name still drives
    the rules. `echo $HOME` grades LOW; `rmdir $dir` grades HIGH.
    """
    resolvable = " ".join(
        t.text for t in tc.tokens if not t.opaque and t.text not in SEPARATORS
    ).strip()
    if not resolvable:
        return RiskLevel.UNKNOWN, "no statically resolvable part in the command"
    return _grade_lines(resolvable)


def describe(level: RiskLevel) -> str:
    """Human-readable risk description (for relaying / dashboard display)."""
    return {
        RiskLevel.UNKNOWN: "UNKNOWN - cannot be judged statically, needs manual confirmation",
        RiskLevel.LOW: "LOW - read-only/safe",
        RiskLevel.MEDIUM: "MEDIUM - has side effects, should be reported",
        RiskLevel.HIGH: "HIGH - should be blocked for manual confirmation",
    }[level]
