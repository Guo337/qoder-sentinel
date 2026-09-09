"""Read-only audit-log inspector used during the debug pass.

Reads the SQLite state store via the public `audit` API.
"""
import collections
import io
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from qoder_guard import audit  # noqa: E402

sys.stdout = io.StringIO()


def out(*args):
    print(*args)


KNOWN = {
    None, "SessionStart", "PreToolUse", "PostToolUse", "PostToolUseFailure",
    "UserPromptSubmit", "hook_bad_input", "unknown",
}
recs = audit.all_records()

out("=== mangled / unexpected event names ===")
for r in recs:
    if r.get("event") not in KNOWN:
        out(json.dumps(r, ensure_ascii=False)[:500])
        out()

out("=== hook_bad_input raw samples ===")
for r in [x for x in recs if x.get("event") == "hook_bad_input"][:10]:
    out(repr(r.get("raw"))[:400])

out()
out("=== Write/Edit risk distribution ===")
c = collections.Counter((r.get("tool"), r.get("risk")) for r in recs if r.get("tool") in ("Write", "Edit"))
for k, v in sorted(c.items(), key=lambda x: str(x)):
    out("   ", k, v)

out()
out("=== tools seen with risk=None but tool present ===")
c2 = collections.Counter(r.get("tool") for r in recs if r.get("tool") and r.get("risk") is None)
for k, v in c2.most_common():
    out("   ", k, v)

pathlib.Path("tools/_inspect_out.txt").write_text(sys.stdout.getvalue(), encoding="utf-8")
