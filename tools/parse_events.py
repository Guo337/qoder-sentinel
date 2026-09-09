"""Parse stream-json output, print event types and key content (read-only analysis)."""
import json
import sys

path = sys.argv[1]
for ln in open(path, encoding="utf-16"):
    ln = ln.strip()
    if not ln.startswith("{"):
        continue
    try:
        o = json.loads(ln)
    except json.JSONDecodeError:
        continue
    t = o.get("type")
    st = o.get("subtype", "")
    print(f"\n--- {t}/{st} ---")
    msg = o.get("message")
    if isinstance(msg, dict) and isinstance(msg.get("content"), list):
        for c in msg["content"]:
            ct = c.get("type")
            if ct == "text":
                print("TEXT:", c.get("text", "")[:400])
            elif ct == "tool_use":
                print("TOOL_USE:", c.get("name"), json.dumps(c.get("input"), ensure_ascii=False)[:300])
            elif ct == "tool_result":
                print("TOOL_RESULT:", str(c.get("content"))[:400], "is_error=", c.get("is_error"))
            elif ct == "thinking":
                print("THINKING:", c.get("thinking", "")[:200])
    if t == "result":
        print("RESULT:", json.dumps({k: o.get(k) for k in ("subtype", "is_error", "result", "permission_denials", "num_turns")}, ensure_ascii=False)[:600])
