import re
from .models import Finding, Evidence

RULES = [
    (
        "AEGIS-SECRET-001",
        "API key",
        re.compile(
            r'''(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_-]{12,})'''
        ),
    ),
    (
        "AEGIS-SECRET-002",
        "Access token",
        re.compile(
            r'''(?i)(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_.-]{16,})'''
        ),
    ),
    (
        "AEGIS-SECRET-003",
        "Password",
        re.compile(
            r'''(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["']([^"']{8,})["']'''
        ),
    ),
    (
        "AEGIS-SECRET-004",
        "JWT secret",
        re.compile(
            r'''(?i)(?:jwt[_-]?secret|jwt[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_-]{16,})'''
        ),
    ),
    (
        "AEGIS-SECRET-005",
        "Private key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    (
        "AEGIS-SECRET-006",
        "Database URL with embedded credentials",
        re.compile(
            r'''(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^/\s:@]+:[^@\s]+@'''
        ),
    ),
    (
        "AEGIS-SECRET-007",
        "Webhook secret",
        re.compile(
            r'''(?i)(?:webhook[_-]?(?:secret|token)|hook[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_-]{16,})'''
        ),
    ),
]

PLACEHOLDER_WORDS = (
    "example_secret",
    "your_api_key",
    "replace_me",
    "changeme",
    "placeholder",
    "dummy",
)

def _is_placeholder(value):
    low = value.lower()
    return any(word in low for word in PLACEHOLDER_WORDS)


def scan_file(path, root):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    out = []
    rel = path.relative_to(root).as_posix()

    for line_no, line in enumerate(text.splitlines(), 1):
        for rule_id, label, pattern in RULES:
            match = pattern.search(line)

            if not match:
                continue

            if match.lastindex:
                value = match.group(1)
                if _is_placeholder(value):
                    continue

            confidence = (
                "HIGH"
                if label in (
                    "Private key",
                    "Database URL with embedded credentials",
                )
                else "MEDIUM"
            )

            out.append(
                Finding(
                    rule_id,
                    f"Potential exposed {label.lower()}",
                    "Secret Exposure",
                    "HIGH",
                    confidence,
                    f"A potential {label.lower()} was detected in source or configuration.",
                    Evidence(rel, line_no, label),
                    "Move sensitive authentication material to a secure secret-management mechanism and rotate any credential that may have been exposed.",
                )
            )

    return out
