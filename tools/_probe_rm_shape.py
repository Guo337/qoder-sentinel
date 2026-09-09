"""Probe: rm/rmdir destructive-shape grading matrix (see SPEC_RM_SHAPE.md)."""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from qoder_guard.risk import RiskLevel, assess  # noqa: E402

# (command, expected level, why the case is pinned)
CASES: list[tuple[str, RiskLevel, str]] = [
    ("rm file.txt", RiskLevel.MEDIUM, "plain delete: same impact class as mv / cp -r / git clean"),
    ("rm -f file.txt", RiskLevel.MEDIUM, "force without recursion is still a single-file delete"),
    ("rm -i a.txt", RiskLevel.MEDIUM, "interactive delete"),
    ("rm --force a.txt", RiskLevel.MEDIUM, "long-form force only, no recursion"),
    ("rm -r dir", RiskLevel.MEDIUM, "recursive without force"),
    ("rm --recursive dir", RiskLevel.MEDIUM, "long-form recursion only"),
    ("rm -rf dir", RiskLevel.HIGH, "recursive AND force together = destructive shape"),
    ("rm -fr dir", RiskLevel.HIGH, "same shape, flags reordered"),
    ("rm -r -f dir", RiskLevel.HIGH, "same shape, separate flag words"),
    ("rm --recursive --force dir", RiskLevel.HIGH, "same shape, long forms"),
    ("rm -rf /", RiskLevel.HIGH, "destructive shape on the root path"),
    ("rm -rf /tmp", RiskLevel.HIGH, "destructive shape (47 audit records)"),
    ("rm -rf \"$DIR\"", RiskLevel.HIGH, "destructive shape, target is a runtime value"),
    # Deviations from the upstream (OpenHands, MIT) shape-only rule: we grade by
    # blast radius instead. `rm "-r" file` is a bounded recursive delete and
    # `rm -r "$FLAGS" /` becomes `rm -r /` when FLAGS is empty, so both sit in
    # the same impact class as `mv` / `cp -r` rather than being dismissed as LOW.
    ("rm -r \"$FLAGS\" /", RiskLevel.MEDIUM, "DEVIATION: empty $FLAGS makes this `rm -r /`"),
    ("rm -f \"$FLAGS\" x", RiskLevel.MEDIUM, "DEVIATION: force plus a runtime flag word"),
    ("rm \"-r\" file", RiskLevel.MEDIUM, "DEVIATION: a recursive delete is a bounded side effect"),
    ("rmdir x", RiskLevel.HIGH, "unchanged: existing rmdir rule is out of scope for this fix"),
    ("echo \"unclosed", RiskLevel.LOW, "benign string that fails to parse is not uncertain"),
    ("rm -rf / \"unclosed", RiskLevel.HIGH, "destructive shape visible in the raw text"),
    ("rm -r dir \"unclosed", RiskLevel.MEDIUM, "recursive only, still visible in the raw text"),
    ("git commit -m \"unclosed", RiskLevel.LOW, "no destructive shape in the raw text"),
]


def main() -> int:
    fails = []
    print("=== rm destructive-shape matrix ===")
    for cmd, expected, why in CASES:
        level, reason = assess("Bash", {"command": cmd})
        ok = level is expected
        print(f"  [{'OK ' if ok else 'BAD'}] {level.value:8} (want {expected.value:8}) {cmd!r}")
        if not ok:
            print(f"        why pinned: {why}")
            print(f"        got reason: {reason}")
            fails.append(f"{cmd!r}: got {level.value}, want {expected.value}")
    print()
    if fails:
        print(f"MISMATCHES ({len(fails)}):")
        for f in fails:
            print("  -", f)
        return 1
    print("_probe_rm_shape: all cases match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
