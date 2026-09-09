"""Independent acceptance probe for qoder_guard/sensitive.py.

Written by the supervising side, NOT by the implementer. The spec's built-in
assertions are the implementer's own tests; this file re-checks the contract
from the outside, including cases the spec did not spell out.

Run: uv run python tools/_probe_sensitive.py   (exit 0 = pass)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qoder_guard import sensitive  # noqa: E402

FAILS: list[str] = []


def _fake(*parts: str) -> str:
    """Join token fragments so no complete token appears in the source.

    Hosted secret scanners match on shape alone, so a realistic fixture in a
    test file is reported as a live credential and blocks the push. Splitting
    the literal keeps the fixture realistic at run time while leaving nothing
    for a scanner to match on disk.
    """
    return "".join(parts)


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        FAILS.append(f"{name}: {detail}")


def kinds(text: str) -> list[str]:
    return [h.kind for h in sensitive.scan(text)]


def main() -> int:
    # 1. contract: non-string / empty input must not raise
    for bad in ("", None, 123, b"bytes", [], {}):
        try:
            r = sensitive.scan(bad)  # type: ignore[arg-type]
            check("scan_non_str_returns_empty", r == (), f"input={bad!r} got={r!r}")
        except Exception as exc:  # noqa: BLE001
            FAILS.append(f"scan_non_str_raised: {bad!r} -> {type(exc).__name__}: {exc}")

    # 2. every hit must carry a valid span and severity
    text = "key=" + _fake("AKIA", "IOSFODNN7", "EXAMPLE") + " mail=a@realcorp.com card=4111 1111 1111 1111"
    hits = sensitive.scan(text)
    check("hits_non_empty", len(hits) >= 3, f"got {len(hits)}")
    for h in hits:
        check("span_in_range", 0 <= h.start < h.end <= len(text), f"{h}")
        check("span_matches", text[h.start:h.end] != "", f"{h}")
        check("severity_valid", h.severity in {sensitive.SEVERITY_HIGH, sensitive.SEVERITY_MEDIUM, sensitive.SEVERITY_LOW}, f"{h}")
        check("label_ascii", all(ord(c) < 128 for c in h.label), f"{h.label}")

    # 3. sorted and non-overlapping
    starts = [h.start for h in hits]
    check("sorted_by_start", starts == sorted(starts), f"{starts}")
    for a, b in zip(hits, hits[1:]):
        check("non_overlapping", a.end <= b.start, f"{a} overlaps {b}")

    # 4. deterministic: same input -> same output
    check("deterministic", sensitive.scan(text) == sensitive.scan(text), "differs between calls")

    # 5. redact round-trip: redacted text must contain no surviving hit
    red = sensitive.redact(text)
    check("redact_removes_all", sensitive.scan(red) == (), f"survivors in {red!r}")
    check("redact_keeps_shape", "<redacted:" in red, red)

    # 6. redact must not raise on non-string
    try:
        sensitive.redact(None)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001
        FAILS.append(f"redact_non_str_raised: {type(exc).__name__}: {exc}")

    # 7. summarize contract
    check("summarize_empty", sensitive.summarize(()) == "no sensitive data", sensitive.summarize(()))
    s = sensitive.summarize(sensitive.scan(text))
    check("summarize_non_empty", s and s != "no sensitive data", s)
    check("summarize_ascii", all(ord(c) < 128 for c in s), s)

    # 8. noise reduction: placeholder values and example domains stay silent
    for clean in (
        "alice@example.com",
        "bob@sub.example.com",
        "API_KEY=your_token_here",
        "TOKEN=changeme",
        "export KEY=${MY_KEY}",
        "echo $HOME",
        "ls -la",
        "1234 5678 9012 3456",
        "1381234567890",
        "cat .gitignore",
    ):
        check("no_false_positive", kinds(clean) == [], f"{clean!r} -> {kinds(clean)}")

    # 9. true positives that matter most
    for sample, expect in (
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private_key"),
        (_fake("AKIA", "IOSFODNN7", "EXAMPLE"), "aws_access_key"),
        ("https://alice:" + _fake("s3cret", "pw") + "@github.com/a/b.git", "url_credentials"),
        ("rm -rf /home/user/.ssh/id_rsa", "ssh_private_key"),
        ("cat ~/.aws/credentials", "cloud_credential"),
        ("DEEPSEEK_API_KEY=" + _fake("abcdef", "1234567890"), "secret_assignment"),
    ):
        check("true_positive", expect in kinds(sample), f"{sample!r} -> {kinds(sample)}")

    # 10. path separators: POSIX and Windows must both be caught
    check("win_ssh_path", "ssh_private_key" in kinds(r"del C:\Users\me\.ssh\id_rsa"), "windows backslash path missed")
    check("win_cloud_path", "cloud_credential" in kinds(r"type C:\Users\me\.aws\credentials"), "windows backslash cloud path missed")

    # 11. ReDoS guard: linear-ish behaviour on adversarial input
    evil = "a" * 40000 + "@" + "b" * 40000
    t0 = time.perf_counter()
    sensitive.scan(evil)
    sensitive.scan("sk-" + "a" * 20000)
    sensitive.scan("AKIA" + "A" * 20000)
    elapsed = time.perf_counter() - t0
    check("no_redos", elapsed < 5.0, f"took {elapsed:.2f}s on 120k chars")

    # 12. large but benign input must stay fast
    t0 = time.perf_counter()
    sensitive.scan("hello world\n" * 20000)
    elapsed = time.perf_counter() - t0
    check("large_input_fast", elapsed < 3.0, f"took {elapsed:.2f}s")

    # 13. hit kind must exist in the declared rule table
    declared = {k for k, *_ in sensitive._RULES}
    for h in sensitive.scan(text):
        check("kind_declared", h.kind in declared, f"{h.kind} not in _RULES")

    if FAILS:
        print(f"FAILED ({len(FAILS)})")
        for f in FAILS:
            print("  -", f)
        return 1
    print("probe_sensitive: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
