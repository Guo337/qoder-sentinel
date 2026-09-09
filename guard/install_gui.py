"""Installer GUI (click to install, upgrade or uninstall the guard).

A window around install.ps1, for the case where running a PowerShell command in
a terminal is the part that stops people. The script does the work; this only
builds the argument list, streams its output into a pane, and shows the state
before and after.

Design mirrors guard/audit_gui.py: the decisions live in pure functions at the
top (what arguments to pass, what the current state is), and the Tk code is a
shell. tools/_probe_install_gui.py tests the pure part.

Nothing runs until a button is pressed, and every action is a command the
command line version already supports.

Usage (from project root):
  uv run python guard/install_gui.py
"""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "install.ps1"
USER_SETTINGS = Path.home() / ".qoder-cn" / "settings.json"
HOOK_MARKER = "observe_hook.py"

# --------------------------------------------------------------------- logic


def build_args(
    install_dir: str = "",
    uninstall: bool = False,
    no_verify: bool = False,
    no_register: bool = False,
    shortcut: bool = False,
    start_menu: bool = False,
) -> list[str]:
    """Argument list for install.ps1, in a stable order.

    Empty strings and false flags are omitted so the script sees its own
    defaults rather than explicit empty values.
    """
    args: list[str] = []
    if install_dir.strip():
        args += ["-Dir", install_dir.strip()]
    if uninstall:
        args.append("-Uninstall")
    if no_verify:
        args.append("-NoVerify")
    if no_register:
        args.append("-NoRegister")
    if shortcut:
        args.append("-Shortcut")
    if start_menu:
        args.append("-StartMenu")
    return args


def hook_command(mode: str = "--check") -> list[str]:
    """Command that inspects or removes the registered hooks."""
    return [
        "uv", "run", "--project", str(ROOT),
        "python", str(ROOT / "guard" / "install_hooks.py"), mode,
    ]


def settings_have_our_hook(settings_path: Path | None = None) -> bool:
    """True when the user settings file mentions our hook script.

    A cheap file read rather than a subprocess, so it can run at startup. It
    answers "is something registered", not "is it registered correctly" - the
    latter needs install_hooks.py --check.
    """
    path = settings_path or USER_SETTINGS
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return HOOK_MARKER in text


def probe_state(root: Path | None = None) -> dict:
    """Facts the window shows before anything is pressed."""
    base = root or ROOT
    return {
        "root": str(base),
        "installer": INSTALLER.is_file(),
        "project": (base / "pyproject.toml").is_file(),
        "uv": shutil.which("uv") or "",
        "hooks_registered": settings_have_our_hook(),
        "settings": str(USER_SETTINGS),
    }


def summarize_state(state: dict) -> list[str]:
    """Human readable lines for the state panel."""
    lines = [
        f"Project      : {state['root']}",
        f"pyproject    : {'found' if state['project'] else 'MISSING'}",
        f"install.ps1  : {'found' if state['installer'] else 'MISSING'}",
        f"uv           : {state['uv'] or 'not found (the installer will try winget)'}",
        f"hooks        : {'registered' if state['hooks_registered'] else 'not registered'}"
        f"  ({state['settings']})",
    ]
    return lines


def powershell_exe() -> str:
    """Prefer Windows PowerShell, fall back to pwsh."""
    return shutil.which("powershell") or shutil.which("pwsh") or "powershell"


def build_powershell_command(args: list[str], script: Path | None = None) -> list[str]:
    """Full command line that runs the installer with the given arguments."""
    target = script or INSTALLER
    return [
        powershell_exe(), "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-File", str(target), *args,
    ]


# ----------------------------------------------------------------------- gui


class InstallerPanel(tk.Tk):
    """Buttons that drive install.ps1, with its output streamed below."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Qoder Sentinel - Installer")
        self.geometry("920x640")
        self.minsize(720, 480)

        self._queue: queue.Queue[str | None] = queue.Queue()
        self._running = False
        self._proc: subprocess.Popen[str] | None = None

        self._build_widgets()
        self._show_state()

    # ------------------------------------------------------------- structure

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        head = ttk.Frame(self, padding=(10, 10, 10, 0))
        head.grid(row=0, column=0, sticky="ew")
        head.columnconfigure(0, weight=1)

        ttk.Label(
            head, text="Install, upgrade or uninstall the Qoder guard",
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            head,
            text="Re-running the install is how you upgrade; audit_logs and .venv are kept.",
        ).grid(row=1, column=0, sticky="w")

        state = ttk.LabelFrame(self, text="Current state", padding=(10, 6, 10, 8))
        state.grid(row=1, column=0, sticky="ew", padx=10, pady=(8, 0))
        state.columnconfigure(0, weight=1)
        self.state_var = tk.StringVar(value="")
        ttk.Label(state, textvariable=self.state_var, justify="left",
                  font=("Consolas", 9)).grid(row=0, column=0, sticky="w")

        options = ttk.LabelFrame(self, text="Options", padding=(10, 6, 10, 8))
        options.grid(row=2, column=0, sticky="ew", padx=10, pady=(8, 0))
        options.columnconfigure(1, weight=1)

        ttk.Label(options, text="Install dir").grid(row=0, column=0, padx=(0, 8), sticky="w")
        self.dir_var = tk.StringVar(value=str(ROOT))
        ttk.Entry(options, textvariable=self.dir_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(options, text="Browse", command=self._browse).grid(
            row=0, column=2, padx=(8, 0))

        self.no_verify_var = tk.BooleanVar(value=False)
        self.no_register_var = tk.BooleanVar(value=False)
        self.shortcut_var = tk.BooleanVar(value=False)
        self.start_menu_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options, text="Skip the self-check (-NoVerify)", variable=self.no_verify_var,
        ).grid(row=1, column=1, sticky="w", pady=(6, 0))
        ttk.Checkbutton(
            options, text="Install files only, do not register hooks (-NoRegister)",
            variable=self.no_register_var,
        ).grid(row=2, column=1, sticky="w")
        ttk.Checkbutton(
            options, text="Create a desktop shortcut for the audit panel",
            variable=self.shortcut_var,
        ).grid(row=3, column=1, sticky="w", pady=(6, 0))
        ttk.Checkbutton(
            options, text="Create a Start menu shortcut as well",
            variable=self.start_menu_var,
        ).grid(row=4, column=1, sticky="w")

        buttons = ttk.Frame(self, padding=(10, 8, 10, 0))
        buttons.grid(row=3, column=0, sticky="ew")
        for col in range(6):
            buttons.columnconfigure(col, weight=0)
        buttons.columnconfigure(5, weight=1)

        self.install_btn = ttk.Button(
            buttons, text="Install / Upgrade", command=self._run_install)
        self.install_btn.grid(row=0, column=0, padx=(0, 8))

        self.uninstall_btn = ttk.Button(
            buttons, text="Uninstall hooks", command=self._run_uninstall)
        self.uninstall_btn.grid(row=0, column=1, padx=(0, 8))

        self.check_btn = ttk.Button(
            buttons, text="Check registration", command=self._run_check)
        self.check_btn.grid(row=0, column=2, padx=(0, 8))

        ttk.Button(buttons, text="Open folder", command=self._open_folder).grid(
            row=0, column=3, padx=(0, 8))

        self.stop_btn = ttk.Button(
            buttons, text="Stop", command=self._stop, state="disabled")
        self.stop_btn.grid(row=0, column=4)

        log_frame = ttk.LabelFrame(self, text="Output", padding=(6, 4, 6, 6))
        log_frame.grid(row=4, column=0, sticky="nsew", padx=10, pady=(8, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log = tk.Text(log_frame, wrap="word", state="disabled",
                           font=("Consolas", 9), background="#1e1e1e",
                           foreground="#e6e6e6", insertbackground="#e6e6e6")
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status_var, padding=(10, 6, 10, 10)).grid(
            row=5, column=0, sticky="w")

    # ----------------------------------------------------------------- state

    def _show_state(self) -> None:
        state = probe_state()
        self.state_var.set("\n".join(summarize_state(state)))

    def _browse(self) -> None:
        chosen = filedialog.askdirectory(
            title="Choose the install directory", initialdir=self.dir_var.get() or str(ROOT))
        if chosen:
            self.dir_var.set(chosen)

    # --------------------------------------------------------------- running

    def _run_install(self) -> None:
        args = build_args(
            install_dir=self.dir_var.get(),
            no_verify=self.no_verify_var.get(),
            no_register=self.no_register_var.get(),
            shortcut=self.shortcut_var.get(),
            start_menu=self.start_menu_var.get(),
        )
        self._start(build_powershell_command(args), "Installing...")

    def _run_uninstall(self) -> None:
        if not messagebox.askyesno(
            "Uninstall hooks",
            "Remove the registered Qoder hooks?\n\nThe installed files are kept.",
        ):
            return
        args = build_args(install_dir=self.dir_var.get(), uninstall=True)
        self._start(build_powershell_command(args), "Removing hooks...")

    def _run_check(self) -> None:
        self._start(hook_command("--check"), "Checking the registration...")

    def _start(self, command: list[str], status: str) -> None:
        if self._running:
            return
        self._running = True
        self._set_buttons(False)
        self.status_var.set(status)
        self._append(f"\n$ {' '.join(command)}\n")

        # Tk is single threaded, so the reader thread only fills a queue and the
        # main thread drains it on a timer.
        def worker() -> None:
            try:
                proc = subprocess.Popen(
                    command, cwd=str(ROOT), stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                    errors="replace", bufsize=1,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                self._proc = proc
                if proc.stdout is not None:
                    for line in proc.stdout:
                        self._queue.put(line.rstrip("\n"))
                code = proc.wait()
            except OSError as exc:
                self._queue.put(f"ERROR: {exc}")
                code = -1
            self._queue.put(f"[exit code {code}]")
            self._queue.put(None)

        threading.Thread(target=worker, daemon=True).start()
        self.after(80, self._drain)

    def _drain(self) -> None:
        """Move whatever the worker produced into the text widget."""
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is None:
                self._finish()
                return
            self._append(item + "\n")
        if self._running:
            self.after(80, self._drain)

    def _finish(self) -> None:
        self._running = False
        self._proc = None
        self._set_buttons(True)
        self._show_state()
        self.status_var.set("Done. Re-check the state above.")

    def _stop(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            self.status_var.set("Stopping...")

    def _set_buttons(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for button in (self.install_btn, self.uninstall_btn, self.check_btn):
            button.configure(state=state)
        self.stop_btn.configure(state="disabled" if enabled else "normal")

    # --------------------------------------------------------------- helpers

    def _append(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _open_folder(self) -> None:
        folder = Path(self.dir_var.get() or str(ROOT))
        if not folder.is_dir():
            messagebox.showinfo("Open folder", f"Not a directory:\n{folder}")
            return
        try:
            os.startfile(str(folder))  # noqa: S606 - Windows shell open
        except (AttributeError, OSError) as exc:
            messagebox.showerror("Could not open the folder", f"{folder}\n{exc}")


def main() -> int:
    InstallerPanel().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
