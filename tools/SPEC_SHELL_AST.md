# SPEC: port the tree-sitter AST layer (MIT, from OpenHands)

## Goal

Add `qoder_guard/shell_ast.py`: a thin, dependency-tolerant wrapper that turns a
shell command string into the list of **every** command it will run, including
commands nested inside structure. The existing regex/`shlex` engine cannot see
structure, so these were graded LOW and escaped (measured 2026-09-08, 13 of 20):

```
(rm -rf /)                        subshell
{ rm -rf /; }                     compound_statement
! rm -rf /                        negated_command
FOO=bar rm -rf /                  variable_assignment prefix
if true; then rm -rf /; fi        if_statement
for f in *; do rm -rf $f; done    for_statement + do_group
while/until ... do rm -rf /; done while_statement + do_group
case x in x) rm -rf /;; esac      case_statement + case_item
f() { rm -rf /; }; f              function_definition + compound_statement
sudo (rm -rf /)                   command containing a subshell
```

## Source to port from (read these first)

- `reference/openhands/shell_parser.py` (75 lines) - parse entry point
- `reference/openhands/_shell_ast.py` (273 lines) - the node views

Both are MIT licensed. Port the *ideas and node-walking logic*, adapted to the
interface below. Do NOT import from `reference/` at runtime: it is a read-only
upstream snapshot, not a package. Copy what you need into the new module.

## Hard requirements

1. **English only.** Every comment, docstring and string literal must be English.
2. **Stdlib + `tree_sitter` + `tree_sitter_bash` only.** No other imports.
3. **Never raise.** Any parse problem, import problem or unexpected node shape
   must degrade to a safe value, never propagate. A hook that crashes is worse
   than a hook that under-grades.
4. **Degrade gracefully.** If `tree_sitter` / `tree_sitter_bash` cannot be
   imported, `AVAILABLE` must be `False` and every public function must still
   return a sane value (`iter_commands` -> `()`, `parse_ok` -> `False`,
   `opaque_head` -> `None`). Import must not fail.
5. **MIT attribution header** at the top of the file:
   ```
   Portions ported from OpenHands software-agent-sdk (MIT License).
   Source: openhands/sdk/security/shell_parser.py, .../_shell_ast.py
   See THIRD_PARTY_LICENSES.md.
   ```
6. Type hints on every public function. `from __future__ import annotations`.
7. Build the `Language` object **once at module import**; build a fresh
   `Parser` **per call** (upstream comment: sharing a parser across calls risks
   interleaved state).

## Public interface (implement exactly)

```python
AVAILABLE: bool

@dataclass(frozen=True, slots=True)
class AstCommand:
    text: str                 # source text of this command node, stripped
    name: str | None          # command_name text, None if absent
    name_opaque: bool         # command_name contains runtime syntax ($, `, etc.)
    words: tuple[str, ...]    # argument words AFTER the command_name
    assignments: tuple[str, ...]  # leading VAR=value words
    opaque: bool              # any word (incl. name) carries runtime syntax

def iter_commands(source: str) -> tuple[AstCommand, ...]
def parse_ok(source: str) -> bool
def opaque_head(source: str) -> str | None   # first opaque command_name, else None
```

### `iter_commands` semantics (the important part)

Return **every** `command` node in the tree, in source order, including nested
ones. Concretely, for `if true; then rm -rf /; fi` return BOTH `true` and
`rm -rf /`. For `(rm -rf /)` return `rm -rf /`. For `f() { rm -rf /; }; f`
return BOTH `rm -rf /` and `f`.

Implementation: walk the whole tree (iterative stack, not recursion) and collect
every node whose `type == "command"`. A node is skipped if it is a
`variable_assignment`-only node (no `command_name` and no words).

### `name_opaque` / `opaque` rules

A word is opaque when its text contains any of: `$` `` ` `` `*` `?` `[` `]`
`{` `}` `~` (runtime expansion, glob, brace or tilde). A `name` is opaque when
the command_name node contains such syntax (`$x`, `$(echo rm)`, `` `whoami` ``).
Windows paths (`C:\...`, `\\server\...`) are NOT opaque; exempt them.

## Verification you must run and report

Run each of these and paste the output in your final message:

```powershell
uv run python -c "from qoder_guard import shell_ast; print(shell_ast.AVAILABLE)"
uv run python -c "
from qoder_guard.shell_ast import iter_commands, parse_ok
for s in ['(rm -rf /)','if true; then rm -rf /; fi','FOO=bar rm -rf /','for f in *; do rm -rf \$f; done','f() { rm -rf /; }; f','echo hi']:
    print(repr(s), '->', [c.text for c in iter_commands(s)])
"
```

Expected shape of the last command (order may vary only if documented):
```
'(rm -rf /)' -> ['rm -rf /']
'if true; then rm -rf /; fi' -> ['true', 'rm -rf /']
'FOO=bar rm -rf /' -> ['rm -rf /']
'for f in *; do rm -rf $f; done' -> ['rm -rf $f']
'f() { rm -rf /; }; f' -> ['rm -rf /', 'f']
'echo hi' -> ['echo hi']
```

## Out of scope (do NOT do)

- Do not modify `qoder_guard/risk.py`.
- Do not modify `qoder_guard/shell_tokens.py`.
- Do not touch `reference/`.
- Do not add any dependency other than the two above.
