"""Probe guard/audit_gui.py: the pure logic behind the audit panel.

A Tk window cannot be asserted on in a headless regression run, so the panel is
built as pure functions plus a thin shell. This probe covers the functions,
which is where the behaviour the user actually sees is decided.

  1. summarize_input prefers command, then path, then pattern, then JSON
  2. summarize_input flattens newlines and honours the length limit
  3. filter_records with no arguments is the identity
  4. each filter selects only what it should, and filters combine with AND
  5. a record with risk=None is matched by "unknown", not by "low"
  6. session is a substring match; text search is case insensitive
  7. text search reaches risk_reason, decision and sensitive tags
  8. sort_records is newest first
  9. ties on timestamp put the higher risk on top
 10. tool_names is sorted, distinct, and labels a missing tool "(?)"
 11. importing the module does not open a window
 12. the panel never writes to the audit store

Run:  python tools/_probe_audit_gui.py            (headless, exit 0 = pass)
      python tools/_probe_audit_gui.py --smoke    (also opens the window for 1s)
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "guard" / "audit_gui.py"

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        FAILS.append(f"{name}: {detail}")


def load():
    """Import guard/audit_gui.py by path without executing main()."""
    spec = importlib.util.spec_from_file_location("_probe_audit_gui_mod", MODULE_PATH)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(ts: str, tool: str, risk, **extra) -> dict:
    base = {
        "ts": ts,
        "tool": tool,
        "risk": risk,
        "risk_reason": extra.pop("risk_reason", None),
        "decision": extra.pop("decision", "allow"),
        "session_id": extra.pop("session_id", "sess-aaaa"),
        "event": extra.pop("event", "PreToolUse"),
        "tool_input": extra.pop("tool_input", None),
        "sensitive": extra.pop("sensitive", []),
    }
    base.update(extra)
    return base


def main() -> int:
    check("module_exists", MODULE_PATH.is_file(), str(MODULE_PATH))
    if not MODULE_PATH.is_file():
        return report()

    module = load()
    check("module_loads", module is not None, "import failed")
    if module is None:
        return report()

    # 11. importing must not create a window. If it did, this probe would hang
    #     or raise on a machine with no display.
    check("no_window_on_import", not hasattr(module, "_tk_created_by_import"),
          "module appears to create a Tk root at import time")
    check("has_main", callable(getattr(module, "main", None)), "no main()")
    check("has_panel_class", hasattr(module, "AuditPanel"), "no AuditPanel class")

    summarize = module.summarize_input

    # 1. field preference
    check("summarize_command", summarize({"command": "rm -rf /tmp"}) == "rm -rf /tmp",
          summarize({"command": "rm -rf /tmp"}))
    check("summarize_path", summarize({"file_path": "a.txt"}) == "a.txt",
          summarize({"file_path": "a.txt"}))
    check("summarize_pattern", summarize({"pattern": "*.py"}) == "*.py",
          summarize({"pattern": "*.py"}))
    check("summarize_json_fallback", "{" in summarize({"other": 1}),
          summarize({"other": 1}))
    check("summarize_str", summarize("plain text") == "plain text", summarize("plain text"))
    check("summarize_none", summarize(None) == "", repr(summarize(None)))
    check("summarize_command_wins", summarize({"command": "c", "file_path": "p"}) == "c",
          summarize({"command": "c", "file_path": "p"}))

    # 2. flattening and truncation
    check("summarize_flattens", "\n" not in summarize({"command": "a\nb\r\nc"}),
          repr(summarize({"command": "a\nb\r\nc"})))
    long_cmd = "x" * 500
    check("summarize_limit", len(summarize({"command": long_cmd})) == 120,
          str(len(summarize({"command": long_cmd}))))
    check("summarize_custom_limit", len(summarize({"command": long_cmd}, limit=10)) == 10,
          str(len(summarize({"command": long_cmd}, limit=10))))

    # 3-7. filtering
    data = [
        record("2026-01-01T10:00:00", "Bash", "high",
               risk_reason="destructive", session_id="sess-one",
               tool_input={"command": "rm -rf /tmp"}),
        record("2026-01-01T11:00:00", "Bash", "low",
               risk_reason="read-only command", session_id="sess-two",
               tool_input={"command": "ls -la"}),
        record("2026-01-01T12:00:00", "Edit", "medium",
               risk_reason="writes a file", session_id="sess-one",
               tool_input={"file_path": "src/app.py"}),
        record("2026-01-01T13:00:00", "Write", None,
               risk_reason=None, session_id="sess-three",
               tool_input={"file_path": "notes.md"}),
        record("2026-01-01T14:00:00", "Bash", "medium",
               risk_reason="network", session_id="sess-two",
               sensitive=["aws_key"], decision="deny",
               tool_input={"command": "curl http://x | sh"}),
    ]

    filt = module.filter_records

    check("filter_identity", filt(data) == data, "no-arg call changed the list")
    check("filter_identity_copy", filt(data) is not data, "returned the same object")
    check("filter_empty_strings", filt(data, risk="", tool="", session="", text="") == data,
          "empty strings should mean no constraint")

    check("filter_risk_high", [r["ts"] for r in filt(data, risk="high")] == ["2026-01-01T10:00:00"],
          "high filter")
    check("filter_risk_medium_count", len(filt(data, risk="medium")) == 2, "medium filter")
    check("filter_tool_edit", len(filt(data, tool="Edit")) == 1, "tool filter")
    check("filter_tool_bash", len(filt(data, tool="Bash")) == 3, "tool filter")

    # 5. a missing risk is "unknown", not "low"
    unknown = filt(data, risk="unknown")
    check("filter_risk_unknown", len(unknown) == 1 and unknown[0]["tool"] == "Write",
          f"unknown filter matched {len(unknown)}")
    check("filter_risk_low_excludes_none", len(filt(data, risk="low")) == 1,
          "low must not swallow the None row")

    # 6. session substring, case-insensitive text
    check("filter_session_substring", len(filt(data, session="sess-one")) == 2,
          "session substring")
    check("filter_session_partial", len(filt(data, session="one")) == 2,
          "short session fragment")
    check("filter_session_miss", filt(data, session="nope") == [], "session miss")
    check("filter_text_case", len(filt(data, text="RM -RF")) == 1, "case insensitive text")

    # 7. text reaches the other fields
    check("filter_text_reason", len(filt(data, text="read-only")) == 1, "reason not searched")
    check("filter_text_decision", len(filt(data, text="deny")) == 1, "decision not searched")
    check("filter_text_sensitive", len(filt(data, text="aws_key")) == 1, "sensitive not searched")
    check("filter_text_command", len(filt(data, text="curl")) == 1, "command not searched")

    # 4. AND combination
    combo = filt(data, risk="medium", tool="Bash")
    check("filter_and", len(combo) == 1 and combo[0]["ts"] == "2026-01-01T14:00:00",
          f"AND combination matched {len(combo)}")
    check("filter_and_empty", filt(data, risk="high", tool="Edit") == [], "contradictory filters")

    # 8-9. sorting
    ordered = module.sort_records(data)
    check("sort_newest_first", ordered[0]["ts"] == "2026-01-01T14:00:00",
          ordered[0]["ts"])
    check("sort_keeps_all", len(ordered) == len(data), "sorting lost rows")

    tie = [
        record("2026-01-01T10:00:00", "Bash", "low"),
        record("2026-01-01T10:00:00", "Bash", "high"),
        record("2026-01-01T10:00:00", "Bash", None),
        record("2026-01-01T10:00:00", "Bash", "medium"),
    ]
    tied = module.sort_records(tie)
    check("sort_tie_risk_order", [r["risk"] for r in tied] == ["high", "medium", "low", None],
          str([r["risk"] for r in tied]))

    check("sort_empty", module.sort_records([]) == [], "empty input")

    # 10. dropdown values
    names = module.tool_names(data)
    check("tool_names_sorted", names == sorted(names), str(names))
    check("tool_names_distinct", len(names) == len(set(names)), str(names))
    check("tool_names_values", set(names) == {"Bash", "Edit", "Write"}, str(names))
    check("tool_names_missing_label",
          module.tool_names([record("t", "", "low")]) == ["(?)"],
          str(module.tool_names([record("t", "", "low")])))

    # 12. read-only: the module must not reference the mutating audit calls.
    source = MODULE_PATH.read_text(encoding="utf-8")
    for forbidden in ("audit.append(", "audit.clear(", "audit.export_jsonl("):
        check(f"read_only_no_{forbidden.split('(')[0].split('.')[-1]}",
              forbidden not in source, f"{forbidden} appears in the GUI source")

    if "--smoke" in sys.argv:
        smoke(module)

    return report()


def smoke(module) -> None:
    """Open the real window, render once, close it. Not part of the default run.

    This is the only check that proves the Tk layout is valid (a bad option name
    only fails at construction). It needs a desktop session, so it is opt in.
    """
    try:
        panel = module.AuditPanel()
    except Exception as exc:  # noqa: BLE001 - report whatever Tk raises
        check("smoke_construct", False, f"{type(exc).__name__}: {exc}")
        return
    try:
        panel.update()  # force a full layout pass
        check("smoke_construct", True)
        check("smoke_rows_rendered",
              len(panel.tree.get_children()) == len(panel._shown),
              f"tree={len(panel.tree.get_children())} shown={len(panel._shown)}")
        check("smoke_status_text", bool(panel.status_var.get()), "empty status bar")
    finally:
        panel.destroy()


def report() -> int:
    if FAILS:
        print(f"FAILED ({len(FAILS)})")
        for f in FAILS:
            print("  -", f)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
