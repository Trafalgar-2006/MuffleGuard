"""Text that a person cannot see but the model reads.

An injection only has to reach the model. It does not have to be visible in the
mail client, so the usual carriers are invisible Unicode, white-on-white HTML
and comments. Revealing these is worth doing on its own: the demo shows the
sentence that was hiding, which is more convincing than a score.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from ..normalize import ZERO_WIDTH, tags_to_ascii

_TAG_RUN_RE = re.compile(r"[\U000E0000-\U000E007F]{4,}")
_ZW_RUN_RE = re.compile(f"[{re.escape(ZERO_WIDTH)}]{{4,}}")
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")

# Inline styles that make text invisible while leaving it in the document.
_INVISIBLE_STYLE = re.compile(
    r"(?is)<([a-z][a-z0-9]*)\b[^>]*style\s*=\s*[\"'][^\"']*"
    r"(?:color\s*:\s*(?:#f{3,6}|white|rgba?\([^)]*(?:255\s*,\s*255\s*,\s*255|,\s*0\s*)\))"
    r"|display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|opacity\s*:\s*0(?!\.[1-9])"
    r"|font-size\s*:\s*0)"
    r"[^\"']*[\"'][^>]*>(.*?)</\1>"
)

_TAG_STRIP_RE = re.compile(r"<[^>]+>")

# Words that make a decoded blob worth reporting. Hidden text that says nothing
# imperative is usually tracking junk, not an attack.
_IMPERATIVE = re.compile(
    r"(?i)\b(ignore|disregard|forget|instead|you must|must now|send|forward|email|"
    r"transfer|delete|execute|run|fetch|post|upload|export|reveal|print|output|"
    r"system prompt|previous instructions|new instructions|urgent|immediately)\b"
)


@dataclass(frozen=True)
class HiddenFinding:
    kind: str
    revealed: str  # the text as the model would read it
    carrier: str  # the raw span it was hiding in

    @property
    def imperative(self) -> bool:
        return bool(_IMPERATIVE.search(self.revealed))


def find_hidden(text: str) -> list[HiddenFinding]:
    """Every piece of text present to the model but not to the reader."""
    findings: list[HiddenFinding] = []

    for m in _TAG_RUN_RE.finditer(text):
        decoded = tags_to_ascii(m.group(0))
        if decoded.strip():
            findings.append(HiddenFinding("unicode_tags", decoded, m.group(0)))

    for m in _ZW_RUN_RE.finditer(text):
        findings.append(
            HiddenFinding("zero_width", f"{len(m.group(0))} zero-width characters", m.group(0))
        )

    for m in _INVISIBLE_STYLE.finditer(text):
        inner = _TAG_STRIP_RE.sub("", m.group(2)).strip()
        if inner:
            findings.append(HiddenFinding("invisible_css", inner, m.group(0)))

    for m in _COMMENT_RE.finditer(text):
        inner = m.group(1).strip()
        if inner and _IMPERATIVE.search(inner):
            findings.append(HiddenFinding("html_comment", inner, m.group(0)))

    for m in _B64_RE.finditer(text):
        decoded = _try_b64(m.group(0))
        if decoded and _IMPERATIVE.search(decoded):
            findings.append(HiddenFinding("base64", decoded, m.group(0)))

    return findings


def _try_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(c.isprintable() or c.isspace() for c in text)
    return text if text and printable / len(text) > 0.9 else None


def strip_hidden(text: str) -> tuple[str, tuple[HiddenFinding, ...]]:
    """Remove hidden carriers so the model reads only what the person sees.

    Anything that gives an order goes, and so does anything written to be
    invisible, whatever it says: text a reader cannot see has no business
    reaching the model either way.
    """
    findings = tuple(find_hidden(text))
    cleaned = text
    for f in findings:
        if f.imperative or f.kind in ("unicode_tags", "zero_width"):
            cleaned = cleaned.replace(f.carrier, "")
    return cleaned, findings
