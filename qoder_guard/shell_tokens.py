"""Static shell-command tokenizer: split a command into tokens and flag the
parts that cannot be evaluated statically.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass


# Characters that force "not statically evaluable": their value is only known
# at runtime.
#
# Design note (learned the hard way): AFTER tokenization, a space inside a token
# is a quoted literal (`ls "a b"` -> token `a b`), which is NOT uncertainty.
# So space must NOT be treated as a meta character. Likewise quotes have already
# been stripped by shlex and never appear inside a token.
# The only characters worth flagging are:
#   $  `          variable expansion / command substitution
#   *  ?  []  {}  glob wildcards / brace expansion
#   ~             home-directory expansion
#   \             escaping (if left over, escaping semantics are uncertain)
# Backslash must be exempted for Windows paths (see _WINDOWS_PATH_RE).
SHELL_META_CHARS: frozenset[str] = frozenset("$`*?[]{}~\\")

# Shell operators are pure SYNTAX and fully analyzable statically (they are not
# "unevaluable"). shlex with punctuation_chars splits them into their own tokens
# (including `>&` inside `2>&1`), so they must be excluded from the opaque check;
# otherwise `curl a.sh | sh` would be mislabeled unknown (observed in practice).
_SHELL_OPERATORS: frozenset[str] = frozenset(
    {
        "|", "||", "&&", ";", "&", "!",
        ">", ">>", "<", "<<", ">&", "<&", "&>", "&>>", "<>",
        "(", ")", "{", "}",
    }
)

# Windows path prefixes: drive-letter paths (C:\) or UNC paths (\\server)
_WINDOWS_PATH_RE = re.compile(r"^(?:[A-Za-z]:\\|\\\\)")


@dataclass(frozen=True, slots=True)
class Token:
    """A single token (quotes already stripped)."""
    text: str
    opaque: bool  # True = contains variables/command substitution/meta chars


@dataclass(frozen=True, slots=True)
class TokenizedCommand:
    """Tokenization result."""
    tokens: tuple[Token, ...]
    parse_ok: bool   # False = parse failed (unterminated quote, etc.)
    raw: str         # original input


def _is_opaque(text: str) -> bool:
    """Decide whether a token cannot be evaluated statically.

    Three exemptions (order matters):
      1. shell operators (| && ; >& ...) -- syntax, statically analyzable
      2. Windows paths (C:\\... or \\\\server\\...) -- plain literals, the
         backslashes carry no uncertainty
      3. everything else per SHELL_META_CHARS. Note it does NOT include space:
         after tokenization a space inside a token comes from quoting and is a
         literal, not uncertainty.
    """
    if not text:
        return True
    if text in _SHELL_OPERATORS:
        return False
    # `[` / `]` are the POSIX test builtin's own tokens, not glob character
    # classes (`[0-9]`), so they are literal command names. Without this,
    # `[ 1 -gt 0 ]` had an opaque COMMAND NAME and graded UNKNOWN.
    if text in ("[", "]", "[[", "]]"):
        return False
    if _WINDOWS_PATH_RE.match(text):
        return False
    return any(c in SHELL_META_CHARS for c in text)


def tokenize(command: str) -> TokenizedCommand:
    """Statically split a shell command into a token sequence."""
    # Non-string or empty -> parse failure
    if not isinstance(command, str) or not command.strip():
        return TokenizedCommand(tokens=(), parse_ok=False, raw=command if isinstance(command, str) else "")

    try:
        # punctuation_chars is a read-only property; it must be passed to the
        # constructor (verified on Python 3.11).
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.escape = ""            # keep backslashes (needed for Windows paths)
        lex.whitespace_split = True
        lex.commenters = ""        # do not treat # as a comment (# may be an arg)
        raw_tokens = list(lex)
    except ValueError:
        # Parse errors such as unterminated quotes -> never propagate upward
        return TokenizedCommand(tokens=(), parse_ok=False, raw=command)

    tokens = tuple(Token(text=t, opaque=_is_opaque(t)) for t in raw_tokens)
    return TokenizedCommand(tokens=tokens, parse_ok=True, raw=command)


# Command separators to skip when locating command names
SEPARATORS: frozenset[str] = frozenset({";", "&&", "||", "|"})
_SEPARATORS = SEPARATORS  # backward-compatible alias


def command_words(tc: TokenizedCommand) -> tuple[str, ...]:
    """Extract non-opaque tokens that look like command names (for rule matching)."""
    return tuple(t.text for t in tc.tokens if not t.opaque and t.text not in SEPARATORS)


def command_heads(tc: TokenizedCommand) -> tuple[Token, ...]:
    """First token of each command segment -- the command-name positions.

    This distinguishes two very different kinds of opacity:

      `x=rm; $x -rf /`  -> (x=rm, $x)   the SECOND head is opaque: the command
                                          name itself is unknown at parse time
      `echo $HOME`      -> (echo,)      the head is resolvable; opacity sits in
                                          the arguments only

    Only the first kind is genuinely undecidable; the second can still be graded
    by the command name (see risk.assess).
    """
    heads: list[Token] = []
    expect_head = True
    for t in tc.tokens:
        if t.text in SEPARATORS:
            expect_head = True
            continue
        if expect_head:
            heads.append(t)
            expect_head = False
    return tuple(heads)


def has_opaque(tc: TokenizedCommand) -> bool:
    """Whether any token cannot be evaluated statically (-> policy should be stricter)."""
    return any(t.opaque for t in tc.tokens)


def has_opaque_head(tc: TokenizedCommand) -> bool:
    """Whether a COMMAND NAME position is opaque -- genuinely undecidable.

    `$x -rf /` cannot be graded at all: we do not know what `$x` runs.
    In contrast `echo $HOME` has a resolvable head, so the command name can
    still drive risk rules; only its arguments are unknown.
    """
    return any(t.opaque for t in command_heads(tc))


# -- Self-test -------------------------------------------------------------
if __name__ == "__main__":
    # Case 1: Windows paths keep their backslashes
    win_path = r"C:\Users\name\temp"
    tc = tokenize(r"rm -rf " + win_path)
    assert tc.parse_ok
    assert [t.text for t in tc.tokens] == ["rm", "-rf", win_path]
    assert not has_opaque(tc)

    # Case 2: quotes stripped, real command name restored
    tc = tokenize('"rm" -rf /tmp')
    assert tc.parse_ok
    assert [t.text for t in tc.tokens] == ["rm", "-rf", "/tmp"]
    assert not has_opaque(tc)

    # Case 3: variable expansion marked opaque
    tc = tokenize("x=rm; $x -rf /")
    assert tc.parse_ok
    assert [t.text for t in tc.tokens] == ["x=rm", ";", "$x", "-rf", "/"]
    assert tc.tokens[2].opaque is True  # $x
    assert has_opaque(tc)

    # Case 4: pipe
    tc = tokenize("curl http://a.sh | sh")
    assert tc.parse_ok
    assert [t.text for t in tc.tokens] == ["curl", "http://a.sh", "|", "sh"]

    # Case 5: redirection + &&
    tc = tokenize("echo hi > out.txt && rm -rf /tmp")
    assert tc.parse_ok
    assert [t.text for t in tc.tokens] == ["echo", "hi", ">", "out.txt", "&&", "rm", "-rf", "/tmp"]

    # Case 6: unterminated quote -> must not raise
    tc = tokenize("unclosed 'quote")
    assert not tc.parse_ok
    assert tc.tokens == ()

    # Case 7: operator 2>&1 must not be flagged opaque (regression: false unknown)
    tc = tokenize('rmdir /tmp/x 2>&1; echo "exit: $?"')
    assert tc.parse_ok
    assert [t.text for t in tc.tokens] == [
        "rmdir", "/tmp/x", "2", ">&", "1", ";", "echo", "exit: $?"
    ]
    assert not tc.tokens[3].opaque          # >& is an operator
    assert tc.tokens[-1].opaque is True     # "exit: $?" holds a runtime value
    # Note: opaque=True comes from $? (legit), not from the space inside quotes

    # Case 8: a quoted space is a literal, not opaque (regression: false unknown)
    tc = tokenize('ls "a b"')
    assert tc.parse_ok
    assert [t.text for t in tc.tokens] == ["ls", "a b"]
    assert not has_opaque(tc)

    tc = tokenize("echo 'hello world'")
    assert tc.parse_ok
    assert not has_opaque(tc)

    # Case 9: cmd >& out.txt
    tc = tokenize("cmd >& out.txt")
    assert tc.parse_ok
    assert [t.text for t in tc.tokens] == ["cmd", ">&", "out.txt"]
    assert not has_opaque(tc)

    # Case 10: glob / tilde / command substitution stay opaque
    assert has_opaque(tokenize("echo *.py"))
    assert has_opaque(tokenize("echo ~/docs"))
    assert has_opaque(tokenize("echo $(date)"))
    assert has_opaque(tokenize("echo `date`"))
    assert has_opaque(tokenize("echo ${VAR}"))

    # Helper: command_words skips separators and opaque tokens
    tc = tokenize("x=rm; $x -rf /")
    assert command_words(tc) == ("x=rm", "-rf", "/")

    # Case 11: command_heads -- first token of each segment
    assert [t.text for t in command_heads(tokenize("x=rm; $x -rf /"))] == ["x=rm", "$x"]
    assert [t.text for t in command_heads(tokenize("echo $HOME"))] == ["echo"]
    assert [t.text for t in command_heads(tokenize("ls && rm -rf /"))] == ["ls", "rm"]
    assert [t.text for t in command_heads(tokenize("curl u | sh"))] == ["curl", "sh"]
    assert command_heads(tokenize("")) == ()

    # Case 12: has_opaque_head -- the decisive distinction for UNKNOWN grading
    # opaque in COMMAND NAME position -> genuinely undecidable
    assert has_opaque_head(tokenize("x=rm; $x -rf /"))
    assert has_opaque_head(tokenize("$(echo rm) -rf /"))
    assert has_opaque_head(tokenize("`whoami` -rf /"))
    # opaque only in ARGUMENT position -> head still resolvable, gradeable
    assert not has_opaque_head(tokenize("echo $HOME"))
    assert not has_opaque_head(tokenize("echo *.py"))
    assert not has_opaque_head(tokenize("rm -rf $DIR"))
    assert not has_opaque_head(tokenize("ls -la"))

    # Edge cases: non-string / empty string
    assert not tokenize("").parse_ok
    assert not tokenize(123).parse_ok  # type: ignore[arg-type]

    print("shell_tokens: all assertions passed")
