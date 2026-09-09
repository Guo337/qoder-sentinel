"""Audit panel GUI (read-only viewer for audit_logs).

The command line version (guard/audit_view.py) prints a fixed summary. This is
the interactive counterpart: filter by risk, tool, session or free text, and
inspect the full record behind any row.

Design: the filtering lives in pure functions at the top of this file, and the
Tk code is only a shell around them. A window cannot be asserted on in a
regression run, but a pure function can, so the logic that decides what the
user sees is tested by tools/_probe_audit_gui.py.

Read-only by design: this panel never writes audit records and never touches the
hook registration. The only write it can perform is the optional JSON export.

Usage (from project root):
  uv run python guard/audit_gui.py
"""
from __future__ import annotations

import json
import os
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qoder_guard import audit  # noqa: E402

# --------------------------------------------------------------------- logic

RISK_LEVELS = ("high", "medium", "low", "unknown")

# Sort key: high first, unknown last. None (no risk recorded) sorts with
# unknown, which is where the SessionStart rows live.
_RISK_RANK = {"high": 0, "medium": 1, "low": 2, None: 3, "unknown": 3}

RISK_LABEL = {None: "unknown", "high": "high", "medium": "medium", "low": "low"}

# Background colours for the tree rows, one per risk level.
RISK_COLOR = {
    "high": "#ffe0e0",
    "medium": "#fff4d6",
    "low": "#e8f6e8",
    None: "#f2f2f2",
}


def summarize_input(tool_input, limit: int = 120) -> str:
    """One-line summary of a tool_input value.

    Mirrors the command line viewer: a command for Bash, a path for file tools,
    otherwise the raw JSON. Newlines are flattened so a row stays one line.
    """
    if isinstance(tool_input, str):
        text = tool_input
    elif isinstance(tool_input, dict):
        text = (
            tool_input.get("command")
            or tool_input.get("file_path")
            or tool_input.get("pattern")
            or json.dumps(tool_input, ensure_ascii=False)
        )
    else:
        text = ""
    return (text or "").replace("\n", " ").replace("\r", " ")[:limit]


def searchable_text(record: dict) -> str:
    """Every field a free-text search should look at, as one string."""
    parts = [
        str(record.get(key) or "")
        for key in ("tool", "risk", "risk_reason", "decision", "session_id", "event")
    ]
    parts.append(summarize_input(record.get("tool_input"), 10_000))
    sensitive = record.get("sensitive")
    if isinstance(sensitive, list):
        parts.extend(str(s) for s in sensitive)
    return " ".join(parts).lower()


def filter_records(
    records: list[dict],
    risk: str | None = None,
    tool: str | None = None,
    session: str | None = None,
    text: str | None = None,
) -> list[dict]:
    """Return the records matching every supplied filter.

    An empty or None filter means "no constraint", so the no-argument call is
    the identity. `session` is a substring match because ids are long and the
    user rarely has the whole thing; `text` is a substring match over
    searchable_text().
    """
    needle = (text or "").strip().lower()
    session_needle = (session or "").strip().lower()
    out: list[dict] = []
    for r in records:
        if risk and (r.get("risk") or "unknown") != risk:
            continue
        if tool and (r.get("tool") or "(?)") != tool:
            continue
        if session_needle and session_needle not in (r.get("session_id") or "").lower():
            continue
        if needle and needle not in searchable_text(r):
            continue
        out.append(r)
    return out


def sort_records(records: list[dict]) -> list[dict]:
    """Newest first; ties broken by risk so the worst row is on top."""
    return sorted(
        records,
        key=lambda r: (r.get("ts") or "", -_RISK_RANK.get(r.get("risk"), 4)),
        reverse=True,
    )


def tool_names(records: list[dict]) -> list[str]:
    """Distinct tool names present in the data, for the dropdown."""
    return sorted({(r.get("tool") or "(?)") for r in records})


# ----------------------------------------------------------------------- gui

class AuditPanel(tk.Tk):
    """Read-only table over the audit store."""

    COLUMNS = (
        ("ts", "Time", 150),
        ("tool", "Tool", 90),
        ("risk", "Risk", 70),
        ("decision", "Decision", 80),
        ("reason", "Reason", 170),
        ("brief", "Command / path", 420),
    )

    def __init__(self) -> None:
        super().__init__()
        self.title("Qoder Sentinel - Execution Audit")
        self.geometry("1180x720")
        self.minsize(820, 480)

        self._records: list[dict] = []
        self._shown: list[dict] = []

        self._build_widgets()
        self.refresh()

    # ------------------------------------------------------------- structure

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=3)
        self.rowconfigure(2, weight=2)

        bar = ttk.Frame(self, padding=(8, 8, 8, 4))
        bar.grid(row=0, column=0, sticky="ew")
        for col in range(10):
            bar.columnconfigure(col, weight=0)
        bar.columnconfigure(9, weight=1)

        ttk.Label(bar, text="Risk").grid(row=0, column=0, padx=(0, 4))
        self.risk_var = tk.StringVar(value="")
        self.risk_box = ttk.Combobox(
            bar, textvariable=self.risk_var, width=10, state="readonly",
            values=("",) + RISK_LEVELS,
        )
        self.risk_box.grid(row=0, column=1, padx=(0, 12))

        ttk.Label(bar, text="Tool").grid(row=0, column=2, padx=(0, 4))
        self.tool_var = tk.StringVar(value="")
        self.tool_box = ttk.Combobox(
            bar, textvariable=self.tool_var, width=12, state="readonly", values=("",),
        )
        self.tool_box.grid(row=0, column=3, padx=(0, 12))

        ttk.Label(bar, text="Session").grid(row=0, column=4, padx=(0, 4))
        self.session_var = tk.StringVar(value="")
        session_entry = ttk.Entry(bar, textvariable=self.session_var, width=18)
        session_entry.grid(row=0, column=5, padx=(0, 12))

        ttk.Label(bar, text="Search").grid(row=0, column=6, padx=(0, 4))
        self.text_var = tk.StringVar(value="")
        search_entry = ttk.Entry(bar, textvariable=self.text_var, width=26)
        search_entry.grid(row=0, column=7, padx=(0, 12))

        ttk.Button(bar, text="Clear", command=self._clear_filters).grid(
            row=0, column=8, padx=(0, 12))

        ttk.Button(bar, text="Refresh", command=self.refresh).grid(row=0, column=9, sticky="w")

        # Any change re-renders immediately; no "apply" button to forget.
        for var in (self.risk_var, self.tool_var):
            var.trace_add("write", lambda *_: self._render())
        for var in (self.session_var, self.text_var):
            var.trace_add("write", lambda *_: self._render())

        table = ttk.Frame(self, padding=(8, 0, 8, 0))
        table.grid(row=1, column=0, sticky="nsew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            table, columns=[c[0] for c in self.COLUMNS], show="headings",
            selectmode="browse",
        )
        for key, label, width in self.COLUMNS:
            self.tree.heading(key, text=label)
            anchor = "w" if key in ("reason", "brief") else "center"
            self.tree.column(key, width=width, anchor=anchor, stretch=(key == "brief"))
        self.tree.grid(row=0, column=0, sticky="nsew")

        yscroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=yscroll.set)

        for risk, color in RISK_COLOR.items():
            self.tree.tag_configure(risk or "none", background=color)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        detail = ttk.LabelFrame(self, text="Record detail", padding=(8, 4, 8, 8))
        detail.grid(row=2, column=0, sticky="nsew", padx=8, pady=(4, 0))
        detail.columnconfigure(0, weight=1)
        detail.rowconfigure(0, weight=1)

        self.detail = tk.Text(detail, height=10, wrap="none", state="disabled",
                              font=("Consolas", 9))
        self.detail.grid(row=0, column=0, sticky="nsew")
        dscroll = ttk.Scrollbar(detail, orient="vertical", command=self.detail.yview)
        dscroll.grid(row=0, column=1, sticky="ns")
        self.detail.configure(yscrollcommand=dscroll.set)

        footer = ttk.Frame(self, padding=(8, 4, 8, 8))
        footer.grid(row=3, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)

        self.status_var = tk.StringVar(value="")
        ttk.Label(footer, textvariable=self.status_var).grid(row=0, column=0, sticky="w")

        ttk.Button(footer, text="Export JSON", command=self._export).grid(
            row=0, column=1, padx=(8, 8))
        ttk.Button(footer, text="Open audit folder", command=self._open_folder).grid(
            row=0, column=2)

    # ------------------------------------------------------------------ data

    def refresh(self) -> None:
        """Reload every record from the store and re-render."""
        self._records = audit.all_records()

        names = [""] + tool_names(self._records)
        self.tool_box.configure(values=names)
        if self.tool_var.get() not in names:
            self.tool_var.set("")

        self._render()

    def _clear_filters(self) -> None:
        self.risk_var.set("")
        self.tool_var.set("")
        self.session_var.set("")
        self.text_var.set("")

    def _render(self) -> None:
        """Apply the filters and rebuild the table."""
        selected = self._selected_index()

        self._shown = sort_records(filter_records(
            self._records,
            risk=self.risk_var.get() or None,
            tool=self.tool_var.get() or None,
            session=self.session_var.get() or None,
            text=self.text_var.get() or None,
        ))

        self.tree.delete(*self.tree.get_children())
        for record in self._shown:
            risk = record.get("risk")
            self.tree.insert(
                "", "end",
                values=(
                    (record.get("ts") or "")[:19].replace("T", " "),
                    record.get("tool") or "(?)",
                    RISK_LABEL.get(risk, "unknown"),
                    record.get("decision") or "",
                    (record.get("risk_reason") or "")[:80],
                    summarize_input(record.get("tool_input")),
                ),
                tags=(risk or "none",),
            )

        total = len(self._records)
        shown = len(self._shown)
        if total == 0:
            self.status_var.set("Audit log is empty - no tasks recorded yet.")
        elif shown == total:
            self.status_var.set(f"Showing all {total} record(s).")
        else:
            self.status_var.set(f"Showing {shown} of {total} record(s).")

        self._restore_selection(selected)

    def _selected_index(self) -> int | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return self.tree.index(sel[0])

    def _restore_selection(self, index: int | None) -> None:
        """Keep the same row selected across a re-render, when it still exists."""
        children = self.tree.get_children()
        if index is not None and 0 <= index < len(children):
            self.tree.selection_set(children[index])
            self.tree.focus(children[index])

    def _on_select(self, _event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        index = self.tree.index(sel[0])
        if not (0 <= index < len(self._shown)):
            return
        record = self._shown[index]
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", json.dumps(record, ensure_ascii=False, indent=2))
        self.detail.configure(state="disabled")

    # ---------------------------------------------------------------- actions

    def _export(self) -> None:
        if not self._shown:
            messagebox.showinfo("Export", "Nothing to export - the current view is empty.")
            return
        path = filedialog.asksaveasfilename(
            title="Export the current view",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            initialfile="audit_view.json",
        )
        if not path:
            return
        try:
            Path(path).write_text(
                json.dumps(self._shown, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self.status_var.set(f"Exported {len(self._shown)} record(s) to {path}")

    def _open_folder(self) -> None:
        folder = audit.log_path().parent
        try:
            folder.mkdir(parents=True, exist_ok=True)
            os.startfile(str(folder))  # noqa: S606 - Windows shell open
        except (AttributeError, OSError) as exc:
            messagebox.showerror("Could not open the folder", f"{folder}\n{exc}")


def main() -> int:
    AuditPanel().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
