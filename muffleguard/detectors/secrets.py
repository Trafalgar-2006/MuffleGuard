"""Secrets and Indian personal data, found by pattern and confirmed by checksum.

This detector is deliberately not a model. A judge can read the rule that fired,
and a random twelve-digit number is not reported as an Aadhaar number because
the Verhoeff checksum rejects it.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

# --- checksums ---------------------------------------------------------------

# Verhoeff tables: multiplication over the dihedral group D5, the permutation
# applied per position, and the inverse used to validate. UIDAI uses this
# checksum for Aadhaar numbers.
_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_ok(digits: str) -> bool:
    """True when the digit string carries a valid Verhoeff check digit."""
    if not digits.isdigit():
        return False
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _D[check][_P[i % 8][int(ch)]]
    return check == 0


def luhn_ok(digits: str) -> bool:
    """True when the digit string carries a valid Luhn check digit (cards)."""
    if not digits.isdigit() or len(digits) < 12:
        return False
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character; random keys sit well above prose."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --- findings ----------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    start: int
    end: int
    confidence: str  # "certain" when a checksum or vendor prefix confirms it

    @property
    def masked(self) -> str:
        """The value with its middle removed, safe to show in a UI or a log."""
        v = self.value
        return v if len(v) <= 8 else f"{v[:4]}...{v[-2:]}"


# Vendor prefixes are unambiguous, so a match alone is conclusive.
_PREFIXED: tuple[tuple[str, str], ...] = (
    ("aws_access_key", r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    ("openrouter_key", r"\bsk-or-v1-[0-9a-f]{64}\b"),
    ("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    ("github_token", r"\bgh[posur]_[A-Za-z0-9]{36,}\b"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    ("stripe_key", r"\b[rs]k_live_[0-9A-Za-z]{16,}\b"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
)

_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_AADHAAR_RE = re.compile(r"\b[2-9][0-9]{3}[ \-]?[0-9]{4}[ \-]?[0-9]{4}\b")
_CARD_RE = re.compile(r"\b(?:[0-9][ \-]?){12,18}[0-9]\b")
_PHONE_RE = re.compile(r"(?<![0-9])(?:\+?91[ \-]?)?[6-9][0-9]{9}(?![0-9])")
_UPI_RE = re.compile(
    r"\b[A-Za-z0-9.\-_]{2,}@(?:okaxis|oksbi|okhdfcbank|okicici|ybl|ibl|axl|paytm|upi|apl|yapl)\b",
    re.IGNORECASE,
)
# A secret assigned to a name that says it is one. Catches keys we have no
# prefix for, which is most of them.
# The name may carry a prefix: DB_PASSWORD and SESSION_TOKEN are how real
# environment files are written, and an underscore is a word character, so
# anchoring on \bpassword would miss both.
_ASSIGNED_RE = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9])\w*(?:api[_\-]?key|secret|token|password|passwd|credential|auth)\w*"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9/+_\-]{16,})[\"']?"
)


def scan(text: str) -> list[Finding]:
    """Every secret or personal identifier in the text, left to right.

    Overlaps are resolved by keeping the first, longest match, so an Aadhaar
    number is not also reported as a phone number.
    """
    found: list[Finding] = []

    def add(kind: str, value: str, start: int, end: int, confidence: str) -> None:
        found.append(Finding(kind, value, start, end, confidence))

    for kind, pattern in _PREFIXED:
        for m in re.finditer(pattern, text):
            add(kind, m.group(0), m.start(), m.end(), "certain")

    for m in _AADHAAR_RE.finditer(text):
        digits = re.sub(r"[ \-]", "", m.group(0))
        if verhoeff_ok(digits):
            add("aadhaar", m.group(0), m.start(), m.end(), "certain")

    for m in _PAN_RE.finditer(text):
        add("pan", m.group(0), m.start(), m.end(), "certain")

    for m in _UPI_RE.finditer(text):
        add("upi", m.group(0), m.start(), m.end(), "certain")

    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[ \-]", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            add("card", m.group(0), m.start(), m.end(), "certain")

    for m in _PHONE_RE.finditer(text):
        add("phone_in", m.group(0), m.start(), m.end(), "likely")

    for m in _ASSIGNED_RE.finditer(text):
        value = m.group(1)
        if shannon_entropy(value) >= 3.0:
            add("assigned_secret", value, m.start(1), m.end(1), "likely")

    return _dedupe(found)


def _dedupe(found: list[Finding]) -> list[Finding]:
    """Drop findings contained in a longer one; prefer the confirmed kind."""
    ordered = sorted(found, key=lambda f: (f.start, -(f.end - f.start), f.confidence != "certain"))
    kept: list[Finding] = []
    for f in ordered:
        if any(k.start <= f.start and f.end <= k.end for k in kept):
            continue
        kept.append(f)
    return kept


def redact(text: str) -> tuple[str, list[Finding]]:
    """The text with every finding masked, and the findings."""
    findings = scan(text)
    out, last = [], 0
    for f in sorted(findings, key=lambda f: f.start):
        out.append(text[last : f.start])
        out.append(f"[{f.kind.upper()} REDACTED]")
        last = f.end
    out.append(text[last:])
    return "".join(out), findings
