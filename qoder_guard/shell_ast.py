"""Tree-sitter AST layer for shell command analysis.

Portions ported from OpenHands software-agent-sdk (MIT License).
Source: openhands/sdk/security/shell_parser.py, .../_shell_ast.py
See THIRD_PARTY_LICENSES.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

try:
    import tree_sitter_bash
    from tree_sitter import Language, Parser

    _BASH_LANGUAGE = Language(tree_sitter_bash.language())
    AVAILABLE: bool = True
except ImportError:
    AVAILABLE = False

_OPAQUE_CHARS = frozenset("$`*?[]{}~")
_WIN_PATH_RE = re.compile(r"^(?:[A-Za-z]:\\|\\\\)")

_COMMAND_SKIP_TYPES = frozenset({
    "command_name",
    "comment",
    "file_redirect",
    "heredoc_redirect",
    "herestring_redirect",
    "redirected_statement",
    "variable_assignment",
})


@dataclass(frozen=True, slots=True)
class AstCommand:
    """A single command extracted from a parsed shell AST."""

    text: str
    name: str | None
    name_opaque: bool
    words: tuple[str, ...]
    assignments: tuple[str, ...]
    opaque: bool


def _node_text(source_bytes: bytes, node: object) -> str:
    try:
        return source_bytes[node.start_byte : node.end_byte].decode()  # type: ignore[union-attr]
    except Exception:
        return ""


def _text_is_opaque(text: str) -> bool:
    if not text:
        return False
    if _WIN_PATH_RE.match(text):
        return False
    return any(c in _OPAQUE_CHARS for c in text)


def _build_command(source_bytes: bytes, node: object) -> AstCommand:
    text = _node_text(source_bytes, node).strip()
    name_text: str | None = None
    name_opaque = False
    words: list[str] = []
    assignments: list[str] = []
    found_name = False

    for child in node.named_children:  # type: ignore[union-attr]
        ctype = child.type
        if ctype == "command_name":
            name_text = _node_text(source_bytes, child)
            name_opaque = _text_is_opaque(name_text)
            found_name = True
        elif ctype == "variable_assignment" and not found_name:
            assignments.append(_node_text(source_bytes, child))
        elif found_name and ctype not in _COMMAND_SKIP_TYPES and "redirect" not in ctype:
            words.append(_node_text(source_bytes, child))

    word_opaque = any(_text_is_opaque(w) for w in words)
    return AstCommand(
        text=text,
        name=name_text,
        name_opaque=name_opaque,
        words=tuple(words),
        assignments=tuple(assignments),
        opaque=name_opaque or word_opaque,
    )


def _try_parse(source: str) -> tuple[object, bytes] | None:
    try:
        source_bytes = source.encode("utf-8")
        parser = Parser(_BASH_LANGUAGE)
        tree = parser.parse(source_bytes)
        return tree.root_node, source_bytes
    except Exception:
        return None


def iter_commands(source: str) -> tuple[AstCommand, ...]:
    """Return every command node in the shell AST, in source order."""
    if not AVAILABLE:
        return ()
    result = _try_parse(source)
    if result is None:
        return ()
    root, source_bytes = result

    commands: list[AstCommand] = []
    stack: list = [root]
    while stack:
        node = stack.pop()
        try:
            if node.type == "command":
                if any(c.type != "variable_assignment" for c in node.named_children):
                    try:
                        commands.append(_build_command(source_bytes, node))
                    except Exception:
                        pass
            for child in reversed(node.children):
                stack.append(child)
        except Exception:
            pass

    return tuple(commands)


def parse_ok(source: str) -> bool:
    """Return True if the source parses without error nodes.

    Empty or whitespace-only input counts as NOT parseable: the grammar accepts
    it without an error node, but there is no command to reason about, and the
    grading engine relies on this verdict to pick its fallback path.
    """
    if not AVAILABLE:
        return False
    if not isinstance(source, str) or not source.strip():
        return False
    result = _try_parse(source)
    if result is None:
        return False
    try:
        return not result[0].has_error  # type: ignore[union-attr]
    except Exception:
        return False


def opaque_head(source: str) -> str | None:
    """Return the first opaque command name, or None."""
    if not AVAILABLE:
        return None
    try:
        for cmd in iter_commands(source):
            if cmd.name_opaque and cmd.name is not None:
                return cmd.name
    except Exception:
        pass
    return None
