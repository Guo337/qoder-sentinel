"""Sensitive data scanning module for qoder-guard.

Detects credentials, tokens, and PII in text using compiled regex rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

_RULES: tuple[tuple[str, str, str, str], ...] = (
    ("private_key", SEVERITY_HIGH,
     r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
     "Private key block"),
    ("aws_access_key", SEVERITY_HIGH,
     r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
     "AWS access key id"),
    ("github_token", SEVERITY_HIGH,
     r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b",
     "GitHub token"),
    ("api_key_prefix", SEVERITY_HIGH,
     r"\bsk-[A-Za-z0-9_-]{20,}\b",
     "OpenAI-style API key"),
    ("slack_token", SEVERITY_HIGH,
     r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
     "Slack token"),
    ("google_api_key", SEVERITY_MEDIUM,
     r"\bAIza[0-9A-Za-z_-]{35}\b",
     "Google API key"),
    ("jwt", SEVERITY_MEDIUM,
     r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
     "JSON Web Token"),
    ("bearer_token", SEVERITY_MEDIUM,
     r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*",
     "Bearer token"),
    ("url_credentials", SEVERITY_HIGH,
     r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@",
     "Credentials in URL"),
    ("secret_assignment", SEVERITY_MEDIUM,
     r"(?i)\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)\s*[=:]\s*\S{8,}",
     "Secret-looking assignment"),
    ("ssh_private_key", SEVERITY_HIGH,
     r"(?i)(?:[/\\]\.ssh[/\\]id_(?:rsa|dsa|ecdsa|ed25519)\b|[/\\]\.ssh[/\\])",
     "SSH private key path"),
    ("cloud_credential", SEVERITY_HIGH,
     r"(?i)(?:[/\\]\.aws[/\\]credentials\b|[/\\]\.config[/\\]gcloud[/\\]|[/\\]\.azure[/\\]|[/\\]\.kube[/\\]config\b)",
     "Cloud credential file"),
    ("dotenv_file", SEVERITY_MEDIUM,
     r"(?i)(?:^|[\s/\\'\"])\.env(?:\.(?:local|production|prod|dev|development|test))?\b",
     ".env file"),
    ("email", SEVERITY_LOW,
     r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
     "Email address"),
    ("cn_mobile", SEVERITY_LOW,
     r"(?<!\d)1[3-9]\d{9}(?!\d)",
     "CN mobile number"),
    ("cn_id_card", SEVERITY_LOW,
     r"(?<!\d)\d{17}[\dXx](?!\d)",
     "CN ID card number"),
    ("card_number", SEVERITY_MEDIUM,
     r"(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)",
     "Card-like number"),
)

_COMPILED: list[tuple[str, str, re.Pattern[str], str]] = [
    (kind, sev, re.compile(pat), label)
    for kind, sev, pat, label in _RULES
]

_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "example.com", "example.org", "example.net", "test.com", "localhost",
    "noreply.github.com", "users.noreply.github.com",
})

_SECRET_PLACEHOLDERS: frozenset[str] = frozenset({
    "your_key_here", "your_token_here", "changeme", "placeholder",
    "xxx", "todo", "<your-key>", "$env_var", "${env_var}", "%env_var%",
})


@dataclass(frozen=True, slots=True)
class SensitiveHit:
    """Single detection result."""

    kind: str
    severity: str
    start: int
    end: int
    label: str

    def span(self) -> tuple[int, int]:
        return (self.start, self.end)


def _is_placeholder_email(domain: str) -> bool:
    d = domain.lower()
    if d in _EMAIL_DOMAINS:
        return True
    if d.endswith(".example.com"):
        return True
    return False


def _is_placeholder_secret(value: str) -> bool:
    if value.startswith("$") or value.startswith("%"):
        return True
    stripped = value.strip("\"'")
    if stripped.lower() in _SECRET_PLACEHOLDERS:
        return True
    return False


def _luhn_ok(digits: str) -> bool:
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def scan(text: str) -> tuple[SensitiveHit, ...]:
    """Return all hits, sorted by (start, end, kind).

    Overlapping hits are de-duplicated: the earlier and longer match wins.
    Never raises.
    """
    if not isinstance(text, str):
        return ()
    if not text:
        return ()

    raw: list[SensitiveHit] = []
    for kind, severity, compiled, label in _COMPILED:
        for m in compiled.finditer(text):
            if kind == "card_number":
                digits = re.sub(r"[ -]", "", m.group())
                if len(digits) != 16 or not _luhn_ok(digits):
                    continue
            elif kind == "email":
                at_idx = m.group().index("@")
                domain = m.group()[at_idx + 1:]
                if _is_placeholder_email(domain):
                    continue
            elif kind == "secret_assignment":
                eq_pos = max(m.group().rfind("="), m.group().rfind(":"))
                value = m.group()[eq_pos + 1:].lstrip()
                if _is_placeholder_secret(value):
                    continue
            raw.append(SensitiveHit(kind, severity, m.start(), m.end(), label))

    raw.sort(key=lambda h: (h.start, -(h.end - h.start), h.kind))

    kept: list[SensitiveHit] = []
    next_free = 0
    for h in raw:
        if h.start >= next_free:
            kept.append(h)
            next_free = h.end

    return tuple(kept)


def has_sensitive(text: str) -> bool:
    """True if scan() returns at least one hit."""
    return len(scan(text)) > 0


def redact(text: str) -> str:
    """Replace every hit span with '<redacted:KIND>'.

    Applies replacements from right to left to keep indices stable.
    Never raises.
    """
    if not isinstance(text, str):
        return text if isinstance(text, str) else ""
    hits = scan(text)
    result = text
    for h in reversed(hits):
        result = result[:h.start] + "<redacted:" + h.kind + ">" + result[h.end:]
    return result


def summarize(hits: tuple[SensitiveHit, ...]) -> str:
    """One-line English summary.

    Example: '2 high, 1 low: github_token x1, email x2'.
    Empty tuple returns 'no sensitive data'.
    """
    if not hits:
        return "no sensitive data"

    sev_counts: dict[str, int] = {}
    kind_counts: dict[str, int] = {}
    for h in hits:
        sev_counts[h.severity] = sev_counts.get(h.severity, 0) + 1
        kind_counts[h.kind] = kind_counts.get(h.kind, 0) + 1

    sev_parts: list[str] = []
    for sev in (SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW):
        c = sev_counts.get(sev, 0)
        if c:
            sev_parts.append(f"{c} {sev}")

    kind_parts = [f"{k} x{kind_counts[k]}" for k in sorted(kind_counts)]

    return ", ".join(sev_parts) + ": " + ", ".join(kind_parts)


def _fake(*parts: str) -> str:
    """Join token fragments so no complete token appears in the source.

    Hosted secret scanners match on shape alone, so a realistic fixture in a
    test file is reported as a live credential and blocks the push. Splitting
    the literal keeps the fixture realistic at run time while leaving nothing
    for a scanner to match on disk.
    """
    return "".join(parts)


if __name__ == "__main__":
    # --- must-hit tests (kind + severity) ---

    h = scan("-----BEGIN RSA PRIVATE KEY-----")
    assert len(h) >= 1
    assert h[0].kind == "private_key"
    assert h[0].severity == SEVERITY_HIGH

    h = scan(_fake("AKIA", "IOSFODNN7", "EXAMPLE"))
    assert len(h) >= 1
    assert h[0].kind == "aws_access_key"
    assert h[0].severity == SEVERITY_HIGH

    h = scan(_fake("ghp_", "0123456789abcdef", "ghijklmnopqrstuvwxyz"))
    assert len(h) >= 1
    assert h[0].kind == "github_token"
    assert h[0].severity == SEVERITY_HIGH

    h = scan(_fake("sk-", "abcdefghijkl", "mnopqrstuvwx"))
    assert len(h) >= 1
    assert h[0].kind == "api_key_prefix"
    assert h[0].severity == SEVERITY_HIGH

    h = scan(_fake("xoxb-", "123456789012-", "abcdefghijklmnop"))
    assert len(h) >= 1
    assert h[0].kind == "slack_token"
    assert h[0].severity == SEVERITY_HIGH

    h = scan(_fake("AIza", "SyA1234567890", "abcdefghijklmnopqrstuv"))
    assert len(h) >= 1
    assert h[0].kind == "google_api_key"
    assert h[0].severity == SEVERITY_MEDIUM

    h = scan(_fake("eyJhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxIn0.",
                   "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g"))
    assert len(h) >= 1
    assert h[0].kind == "jwt"
    assert h[0].severity == SEVERITY_MEDIUM

    h = scan("Authorization: Bearer " + _fake("abcdefghijklmnop", "qrstuvwxyz123456"))
    assert len(h) >= 1
    assert h[0].kind == "bearer_token"
    assert h[0].severity == SEVERITY_MEDIUM

    h = scan("https://alice:" + _fake("s3cret", "pw") + "@github.com/foo/bar.git")
    assert len(h) >= 1
    assert h[0].kind == "url_credentials"
    assert h[0].severity == SEVERITY_HIGH

    h = scan("DEEPSEEK_API_KEY=" + _fake("abcdef", "1234567890"))
    assert len(h) >= 1
    assert h[0].kind == "secret_assignment"
    assert h[0].severity == SEVERITY_MEDIUM

    h = scan("rm -rf /home/user/.ssh/id_rsa")
    assert len(h) >= 1
    assert h[0].kind == "ssh_private_key"
    assert h[0].severity == SEVERITY_HIGH

    h = scan("cat ~/.aws/credentials")
    assert len(h) >= 1
    assert h[0].kind == "cloud_credential"
    assert h[0].severity == SEVERITY_HIGH

    h = scan('echo "hello" > .env.local')
    assert len(h) >= 1
    assert h[0].kind == "dotenv_file"
    assert h[0].severity == SEVERITY_MEDIUM

    h = scan("alice@realcorp.com")
    assert len(h) >= 1
    assert h[0].kind == "email"
    assert h[0].severity == SEVERITY_LOW

    h = scan("13812345678")
    assert len(h) >= 1
    assert h[0].kind == "cn_mobile"
    assert h[0].severity == SEVERITY_LOW

    h = scan("4111 1111 1111 1111")
    assert len(h) >= 1
    assert h[0].kind == "card_number"
    assert h[0].severity == SEVERITY_MEDIUM

    # --- must-not-hit tests ---

    assert scan("alice@example.com") == ()
    assert scan("your_key_here") == ()
    assert scan("API_KEY=your_token_here") == ()
    assert scan("export API_KEY=$MY_KEY") == ()
    assert scan("export API_KEY=${MY_KEY}") == ()
    assert scan("echo $HOME") == ()
    assert scan("ls -la") == ()
    assert scan("1234 5678 9012 3456") == ()
    assert scan("1381234567890") == ()
    assert scan("20260909") == ()
    assert scan(".gitignore") == ()

    # --- edge cases ---

    assert scan("") == ()
    assert scan(None) == ()  # type: ignore[arg-type]
    assert has_sensitive(_fake("sk-", "abcdefghijkl", "mnopqrstuvwx")) is True
    assert has_sensitive("hello world") is False
    assert summarize(()) == "no sensitive data"

    # --- redact ---

    r = redact("key=" + _fake("sk-", "abcdefghijkl", "mnopqrstuvwx") + " done")
    assert "<redacted:api_key_prefix>" in r
    assert "sk-" not in r

    print("All assertions passed.")
