"""Qoder hook event handler.

Qoder CLI invokes our registered hook scripts with stdin JSON during the tool
call lifecycle. This module normalizes "raw events" into audit records and
(participates in blocking decisions in stage B).

Official contract (https://docs.qoder.com/cli/hooks,
reference https://docs.qoder.com/cli/hooks-reference):
  - Events: PreToolUse / PostToolUse / PostToolUseFailure / UserPromptSubmit ...
  - command-type hooks receive JSON via stdin, containing session_id / cwd /
    hook_event_name and other common fields, plus event-specific fields
    (PreToolUse includes tool_name / tool_input)
  - Exit codes: 0 = success/allow; 2 = block (stderr feedback to agent)
  - On exit code 0, stdout can output JSON for fine-grained control
  - hookSpecificOutput.permissionDecision in {"allow", "deny", "ask"} takes
    precedence over the top-level decision; only it supports "ask"
  - hookSpecificOutput.permissionDecisionReason  -> feedback text
  - hookSpecificOutput must include hookEventName, or the whole JSON is rejected
Also available: additionalContext / updatedInput / updatedToolOutput /
updatedMCPToolOutput.

[Behaviour verified against v1.1.45 (2026-09-08), black-box only]
Tested: PreToolUse returning permissionDecision="deny" causes CLI to output
"Cancelling..." and end with result/error_during_execution (num_turns=1, model
did not start), exit code 1.
-- This shows "blocking" works in headless mode, but "asking" (ask) has no
   interactive UI in -p mode; stage B needs to implement "external inquiry"
   itself (see README stage B evaluation).
"""
from __future__ import annotations

import json
import sys

from . import audit, review
from . import sensitive as sensitive_mod
from .policy import Decision, DenyRisky, NeverAsk, PolicyBase
from .risk import assess, describe
from .shell_tokens import has_opaque, tokenize

# Only these events support blocking (deny is meaningless for other events)
BLOCKABLE_EVENTS = {"PreToolUse", "PermissionRequest"}

# Default policy: observation mode (allow all). Stage B switches to DenyRisky via env var QGUARD_BLOCK.
# Note: use DenyRisky not AskRisky: headless (-p) mode has no interactive UI,
# ASK equals allow, providing no blocking effect -- unattended scenarios must DENY directly.
DEFAULT_POLICY: PolicyBase = NeverAsk()
BLOCK_POLICY: PolicyBase = DenyRisky(threshold="high")


def _extract_tool(event: dict) -> tuple[str, object]:
    """Extract (tool_name, tool_input) from the event. Field names based on testing; try multiple fallbacks."""
    tool_name = event.get("tool_name") or event.get("toolName") or ""
    tool_input = event.get("tool_input") or event.get("toolInput") or {}

    # Some implementations embed tool name inside input / top-level
    if not tool_name:
        inner = event.get("input") or {}
        if isinstance(inner, dict):
            tool_name = inner.get("name") or inner.get("tool_name") or ""
            tool_input = inner.get("input") or inner.get("tool_input") or {}
    return tool_name, tool_input


def _deny_output(reason: str, event_name: str) -> str:
    """Generate stdout JSON for a deny decision (tested to work)."""
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, ensure_ascii=False)


# Argument fields that carry the analyzable command/body text.
_TEXT_KEYS = ("command", "description", "params", "query", "input", "code", "content")

# Argument fields that identify WHICH target a call acts on. They must be part
# of a review fingerprint: Write has no `command`, so keying on `content` alone
# would let one approval cover the same text written to a different path.
_IDENTITY_KEYS = ("file_path", "filepath", "path", "notebook_path", "url", "pattern")


def _pick_fields(tool_input: object, keys: tuple[str, ...]) -> str:
    """Join the values of `keys` found in tool_input (case-insensitive)."""
    if isinstance(tool_input, str):
        return tool_input
    if isinstance(tool_input, dict):
        lowered = {str(k).lower(): v for k, v in tool_input.items()}
        return " ".join(str(lowered[k]) for k in keys if k in lowered)
    return ""


def _command_text(tool_input: object) -> str:
    """Analyze text of a tool call, used for opacity checks and risk grading."""
    return _pick_fields(tool_input, _TEXT_KEYS)


def _fingerprint_text(tool_input: object) -> str:
    """Identity of a tool call: analyzable text plus the target it acts on.

    Approvals are cached by this string, so it must be specific enough that
    approving one target never widens permission for another.
    """
    return " ".join(
        part for part in (
            _pick_fields(tool_input, _IDENTITY_KEYS),
            _pick_fields(tool_input, _TEXT_KEYS),
        ) if part
    )


# The field that carries a command line. Secrets here are about to be handed to
# a process (and to its logs), so they are the ones we refuse outright. Text in
# other fields (e.g. Write's `content`) is the user's own file payload and is
# only recorded, never used to block: blocking there would reject legitimate
# fixtures and documentation that quote example credentials.
_COMMAND_KEYS = ("command",)

# Highest severity present, or None when nothing was found.
_SEVERITY_RANK = {
    sensitive_mod.SEVERITY_LOW: 0,
    sensitive_mod.SEVERITY_MEDIUM: 1,
    sensitive_mod.SEVERITY_HIGH: 2,
}


def _scan_sensitive(tool_input: object) -> tuple[tuple, str | None]:
    """Scan a tool call for credentials/PII.

    Returns (hits, max_severity). `hits` are limited to the command field so the
    caller can tell whether the secret is about to be executed; the rest of the
    text is still scanned for the audit trail.
    """
    command = _pick_fields(tool_input, _COMMAND_KEYS)
    hits = sensitive_mod.scan(command) if command else ()
    max_sev: str | None = None
    for h in hits:
        if max_sev is None or _SEVERITY_RANK.get(h.severity, 0) > _SEVERITY_RANK.get(max_sev, 0):
            max_sev = h.severity
    return hits, max_sev


def _redact_input(tool_input: object) -> object:
    """Return tool_input with credential values masked before it is persisted.

    The audit log is an evidence store, not a credential store: writing a live
    token into SQLite would turn the guard itself into the leak. Only string
    leaves are rewritten; the shape of the event is preserved.
    """
    if isinstance(tool_input, str):
        return sensitive_mod.redact(tool_input)
    if isinstance(tool_input, dict):
        return {
            k: (sensitive_mod.redact(v) if isinstance(v, str) else v)
            for k, v in tool_input.items()
        }
    return tool_input


def _resolve_review(tool_name: str, text: str, reason: str | None,
                    session_id: str | None) -> tuple[Decision, str | None]:
    """Handle a REVIEW decision: replay a cached approval or queue it.

    Returns (decision, review_id). A cached allow/deny wins immediately; on a
    first sighting the request is queued and the call is denied with a reason
    that tells the supervising agent exactly which id to approve. This keeps
    the hook non-blocking: no timeout, no polling, no chance of stalling a task.
    """
    fp = review.fingerprint(tool_name or "(none)", text)
    cached = review.lookup(fp)
    if cached is not None:
        if cached.get("decision") == review.DECISION_ALLOW:
            return Decision.ALLOW, fp
        return Decision.DENY, fp

    review.enqueue(tool_name or "(none)", text, reason or "", session_id=session_id,
                   fingerprint_id=fp)
    return Decision.DENY, fp


def handle_stdin(raw: str, *, block_high_risk: bool = False) -> int:
    """Handle a single hook invocation.

    Args:
      raw              raw stdin text received by the hook
      block_high_risk  stage B switch: when True, high-risk operations are blocked
    Returns:
      exit code (0 = allow, 2 = block)

    Design principle: **the observer's own failure must never block the task**.
    Any unexpected exception degrades to allow (exit code 0) while leaving an
    audit trail, so the guard layer does not become a fault source itself.
    """
    try:
        return _handle(raw, block_high_risk=block_high_risk)
    except Exception as exc:  # noqa: BLE001 -- fallback must be broad
        # Own crash must not drag down the task; leave a diagnosable trace if possible
        try:
            audit.append({
                "event": "hook_internal_error",
                "error": f"{type(exc).__name__}: {exc}",
                "raw": raw[:500],
            })
        except Exception:
            pass
        return 0


def _handle(raw: str, *, block_high_risk: bool = False) -> int:
    """Actual hook processing logic (exceptions caught by handle_stdin fallback)."""
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        # Received non-JSON: record but never block the task due to observer's own failure
        audit.append({"event": "hook_bad_input", "raw": raw[:500]})
        return 0

    if not isinstance(event, dict):
        audit.append({"event": "hook_bad_input", "raw": raw[:500]})
        return 0

    hook_event = event.get("hook_event_name") or event.get("event") or "unknown"
    tool_name, tool_input = _extract_tool(event)

    # Only tool-related events get risk assessment; session start/end etc. are just logged, not flagged
    tool_events = {"PreToolUse", "PostToolUse", "PostToolUseFailure"}
    if hook_event in tool_events:
        level, reason = assess(tool_name, tool_input)
    else:
        level, reason = None, None

    # Whether it contains fragments that cannot be statically evaluated (for conservative policy decisions)
    opaque = False
    if hook_event in tool_events:
        _text = _command_text(tool_input)
        if _text.strip():
            opaque = has_opaque(tokenize(_text))

    # Sensitive data in a command line: a live credential is about to be handed
    # to a process. This is independent of the risk grade -- `export K=<token>`
    # is a harmless-looking command that leaks a secret -- so it is decided
    # before the policy layer and only when blocking is enabled.
    sensitive_hits: tuple = ()
    sensitive_severity: str | None = None
    if hook_event in tool_events:
        sensitive_hits, sensitive_severity = _scan_sensitive(tool_input)

    # Stage B decision: policy layer decides allow/ask/deny (analyzer only scores, policy only decides)
    policy: PolicyBase = BLOCK_POLICY if block_high_risk else DEFAULT_POLICY
    decision = policy.decide(level.value if level else None, has_opaque=opaque)
    if block_high_risk and sensitive_severity == sensitive_mod.SEVERITY_HIGH:
        # An outright secret beats a risk grade: never execute it.
        decision = Decision.DENY
    review_id: str | None = None
    # Only blockable events may touch the review queue. A PostToolUse event for
    # the same command must not enqueue a request: the command already ran, and
    # enqueuing would leave a phantom "pending" entry with no way to execute it.
    if decision is Decision.REVIEW and hook_event in BLOCKABLE_EVENTS:
        # UNKNOWN is unrankable: hand it to the supervising agent instead of
        # guessing. A cached approval replays instantly; otherwise the call is
        # denied once and queued (see review.py for the file protocol).
        decision, review_id = _resolve_review(
            tool_name, _fingerprint_text(tool_input), reason,
            event.get("session_id"),
        )
    if hook_event not in BLOCKABLE_EVENTS:
        decision = Decision.ALLOW  # Non-blockable event; decision is meaningless

    # Always write to audit regardless -- this is the "execution history independent of conversation logs"
    audit.append({
        "event": hook_event,
        "session_id": event.get("session_id"),
        "cwd": event.get("cwd"),
        "agent_id": event.get("agent_id") or event.get("agentId"),
        "permission_mode": event.get("permission_mode"),
        "tool": tool_name or "(none)",
        # Credentials are masked before persistence: the audit log is evidence,
        # not a secret store.
        "tool_input": _redact_input(tool_input) if hook_event in tool_events else None,
        "risk": level.value if level else None,
        "risk_reason": reason,
        "opaque": opaque,
        "sensitive": [h.kind for h in sensitive_hits],
        "sensitive_severity": sensitive_severity,
        "review_id": review_id,
        "decision": decision.value,
        "hook_blocked": decision is Decision.DENY,
    })

    if decision is Decision.DENY:
        if review_id:
            msg = (
                f"HELD FOR REVIEW by guard layer: {describe(level)} -- {reason}\n"
                f"Review id: {review_id}\n"
                f"To approve, run: python guard/review.py approve {review_id}\n"
                f"To reject, run:  python guard/review.py deny {review_id}"
            )
        elif sensitive_severity == sensitive_mod.SEVERITY_HIGH:
            kinds = ", ".join(sorted({h.kind for h in sensitive_hits}))
            msg = (
                f"DENIED by guard layer: sensitive data in command line "
                f"({kinds}). Remove the credential or read it from the environment "
                f"instead of inlining it."
            )
        else:
            msg = f"DENIED by guard layer: {describe(level)} -- {reason}"
        # Prefer stdout JSON (tested protocol); stderr for human visibility; exit code 2 as fallback
        print(_deny_output(msg, hook_event))
        print(msg, file=sys.stderr)
        return 2

    return 0
