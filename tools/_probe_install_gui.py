"""Probe guard/install_gui.py: the pure logic behind the installer window.

The window itself cannot be asserted on in a headless run, so the decisions are
pure functions. This probe covers those, which is where a wrong button would
actually come from.

  1. build_args omits defaults, so install.ps1 sees its own values
  2. build_args includes -Dir only when a directory was given, and strips it
  3. each switch maps to exactly one flag
  4. the flag order is stable
  5. hook_command targets the right script and mode
  6. build_powershell_command is bypass-safe and non-interactive
  7. settings_have_our_hook detects the marker and tolerates a missing file
  8. probe_state reports the real facts about this checkout
  9. summarize_state is one line per fact and names the settings path
 10. importing the module does not open a window
 11. the GUI never runs the installer at import time
 12. the shortcut options are opt in and reach install.ps1

Run:  python tools/_probe_install_gui.py            (headless, exit 0 = pass)
      python tools/_probe_install_gui.py --smoke    (also opens the window)
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "guard" / "install_gui.py"

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
    spec = importlib.util.spec_from_file_location("_probe_install_gui_mod", MODULE_PATH)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    check("module_exists", MODULE_PATH.is_file(), str(MODULE_PATH))
    if not MODULE_PATH.is_file():
        return report()

    module = load()
    check("module_loads", module is not None, "import failed")
    if module is None:
        return report()

    # 10-11. a window must not appear and nothing may run on import
    check("no_window_on_import", not hasattr(module, "_panel_created_by_import"),
          "module creates a Tk root at import time")
    check("has_main", callable(getattr(module, "main", None)), "no main()")
    check("has_panel_class", hasattr(module, "InstallerPanel"), "no InstallerPanel class")

    build = module.build_args

    # 1. defaults produce no arguments at all
    check("args_all_default", build() == [], str(build()))
    check("args_whitespace_dir", build(install_dir="   ") == [], str(build("   ")))

    # 2-3. each input maps to exactly one flag
    check("args_dir", build(install_dir="D:\\tools\\qs") == ["-Dir", "D:\\tools\\qs"],
          str(build("D:\\tools\\qs")))
    check("args_dir_stripped", build(install_dir="  C:\\a  ") == ["-Dir", "C:\\a"],
          str(build("  C:\\a  ")))
    check("args_uninstall", build(uninstall=True) == ["-Uninstall"], str(build(uninstall=True)))
    check("args_no_verify", build(no_verify=True) == ["-NoVerify"], str(build(no_verify=True)))
    check("args_no_register", build(no_register=True) == ["-NoRegister"],
          str(build(no_register=True)))

    # 4. order is stable regardless of how the caller passes them
    full = build(install_dir="C:\\x", uninstall=True, no_verify=True, no_register=True)
    check("args_order", full == ["-Dir", "C:\\x", "-Uninstall", "-NoVerify", "-NoRegister"],
          str(full))
    check("args_no_duplicates", len(full) == len(set(full)), str(full))

    # 12. shortcut switches: off by default, each maps to its own flag, and they
    #     come after the existing ones so the stable order is preserved.
    check("args_shortcut_default_off",
          "-Shortcut" not in build() and "-StartMenu" not in build(), str(build()))
    check("args_shortcut", build(shortcut=True) == ["-Shortcut"], str(build(shortcut=True)))
    check("args_start_menu", build(start_menu=True) == ["-StartMenu"],
          str(build(start_menu=True)))
    both = build(shortcut=True, start_menu=True)
    check("args_shortcut_both", both == ["-Shortcut", "-StartMenu"], str(both))
    check("args_shortcut_order",
          build(install_dir="C:\\x", shortcut=True, start_menu=True) ==
          ["-Dir", "C:\\x", "-Shortcut", "-StartMenu"],
          str(build(install_dir="C:\\x", shortcut=True, start_menu=True)))

    # 5. hook inspection command
    check_cmd = module.hook_command("--check")
    check("hook_cmd_check_flag", check_cmd[-1] == "--check", str(check_cmd))
    check("hook_cmd_script", check_cmd[-2].endswith("install_hooks.py"), str(check_cmd))
    check("hook_cmd_project", "--project" in check_cmd, str(check_cmd))
    check("hook_cmd_remove", module.hook_command("--remove")[-1] == "--remove",
          str(module.hook_command("--remove")))

    # 6. the PowerShell invocation must not prompt and must bypass the policy
    cmd = module.build_powershell_command(["-NoVerify"])
    check("ps_no_profile", "-NoProfile" in cmd, str(cmd))
    check("ps_non_interactive", "-NonInteractive" in cmd, str(cmd))
    check("ps_bypass", "-ExecutionPolicy" in cmd and "Bypass" in cmd, str(cmd))
    check("ps_file_flag", "-File" in cmd, str(cmd))
    check("ps_targets_installer", any(str(module.INSTALLER) == part for part in cmd), str(cmd))
    check("ps_passes_args", cmd[-1] == "-NoVerify", str(cmd))

    # 7. settings detection
    with tempfile.TemporaryDirectory() as tmp:
        settings = pathlib.Path(tmp) / "settings.json"
        check("settings_missing", module.settings_have_our_hook(settings) is False,
              "a missing file must not raise")
        settings.write_text('{"hooks": {}}', encoding="utf-8")
        check("settings_empty", module.settings_have_our_hook(settings) is False,
              "an unrelated file must not match")
        settings.write_text(
            '{"hooks": {"PreToolUse": "python C:/x/guard/observe_hook.py"}}',
            encoding="utf-8",
        )
        check("settings_marker", module.settings_have_our_hook(settings) is True,
              "the marker was not detected")

    # 8. state of this checkout
    state = module.probe_state()
    check("state_keys", set(state) == {
        "root", "installer", "project", "uv", "hooks_registered", "settings"},
        str(sorted(state)))
    check("state_root", state["root"] == str(ROOT), state["root"])
    check("state_installer", state["installer"] is True, "install.ps1 not found")
    check("state_project", state["project"] is True, "pyproject.toml not found")
    check("state_uv", bool(state["uv"]), "uv was not detected")
    check("state_hooks_bool", isinstance(state["hooks_registered"], bool),
          str(type(state["hooks_registered"])))

    # 9. the summary is renderable and mentions the settings file
    lines = module.summarize_state(state)
    check("summary_lines", len(lines) >= 5, str(len(lines)))
    check("summary_no_newline", all("\n" not in ln for ln in lines), "a line contains a newline")
    check("summary_mentions_settings", any(".qoder-cn" in ln for ln in lines), str(lines))
    check("summary_labels", any("uv" in ln for ln in lines) and
          any("hooks" in ln for ln in lines), str(lines))

    if "--smoke" in sys.argv:
        smoke(module)

    return report()


def smoke(module) -> None:
    """Construct the real window, lay it out, close it. Opt in, needs a desktop."""
    try:
        panel = module.InstallerPanel()
    except Exception as exc:  # noqa: BLE001 - report whatever Tk raises
        check("smoke_construct", False, f"{type(exc).__name__}: {exc}")
        return
    try:
        panel.update()
        check("smoke_construct", True)
        check("smoke_state_shown", bool(panel.state_var.get()), "state panel is empty")
        check("smoke_dir_default", panel.dir_var.get() == str(module.ROOT),
              panel.dir_var.get())
        check("smoke_shortcut_off", panel.shortcut_var.get() is False and
              panel.start_menu_var.get() is False,
              f"shortcut={panel.shortcut_var.get()} startmenu={panel.start_menu_var.get()}")
        check("smoke_buttons_idle",
              str(panel.install_btn["state"]) == "normal" and
              str(panel.stop_btn["state"]) == "disabled",
              f"install={panel.install_btn['state']} stop={panel.stop_btn['state']}")
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
