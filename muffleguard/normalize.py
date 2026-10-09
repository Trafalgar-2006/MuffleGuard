"""Text normalisation primitives shared by the ledger, the policy and the detectors.

Matching a tool-call argument against what the agent has read is the base of the
whole guard, so normalisation has one job: make the *same* string written two
ways compare equal, without ever making two *different* strings compare equal.

That asymmetry is why confusable characters are not folded here. Folding
Cyrillic "а" onto Latin "a" would make the homograph address
"аlice@corp.example" match a user who typed "alice@corp.example", and the guard
would allow mail to the attacker's lookalike domain. Homographs are reported by
`mixed_script` instead, and the policy treats them as hostile.
"""

from __future__ import annotations

import re
import unicodedata

# Characters that carry no visible mark but survive a copy-paste, so they are a
# standard way to hide instructions inside otherwise innocent text.
ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff"
BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
# Unicode Tag block: an invisible copy of ASCII, used to smuggle prompts.
TAGS = "".join(chr(c) for c in range(0xE0000, 0xE0080))
INVISIBLE = ZERO_WIDTH + BIDI + TAGS + "\u00ad"

_INVISIBLE_RE = re.compile(f"[{re.escape(INVISIBLE)}]")
_WS_RE = re.compile(r"\s+")

# Scripts that supply lookalikes for Latin letters.
_CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")


def strip_invisible(text: str) -> tuple[str, str]:
    """Return the text without invisible characters, and the characters removed."""
    removed = "".join(_INVISIBLE_RE.findall(text))
    return _INVISIBLE_RE.sub("", text), removed


def tags_to_ascii(text: str) -> str:
    """Decode Unicode Tag characters back to the ASCII they mirror.

    Instructions hidden this way are invisible in a mail client but are read by
    the model exactly as if they had been typed.
    """
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0000 <= ord(c) <= 0xE007F)


def normalize(text: str) -> str:
    """Fold the ways one string can be written: width, case, spacing, invisibles.

    NFKC is what turns fullwidth and styled letters back into plain ASCII, so
    "ｓｅｎｄ" and "send" compare equal.
    """
    text = unicodedata.normalize("NFKC", text)
    text, _ = strip_invisible(text)
    return _WS_RE.sub(" ", text).strip().casefold()


def mixed_script(value: str) -> bool:
    """True when letters from a confusable script sit beside Latin letters.

    A real address is written in one script. A mix is a homograph attack.
    """
    has_latin = False
    has_other = False
    for ch in value:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        if name.startswith("LATIN"):
            has_latin = True
        elif name.startswith(_CONFUSABLE_SCRIPTS):
            has_other = True
    return has_latin and has_other


# Deliberately Unicode-aware. An ASCII-only pattern would skip the Cyrillic
# letter in "аlice@corp.example" and extract the remainder, "lice@corp.example",
# which is a substring of the real address and would be taken for it.
EMAIL_RE = re.compile(r"[\w.%+\-]+@[\w\-]+(?:\.[\w\-]+)+", re.UNICODE)
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_BARE_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)


def emails_in(text: str) -> list[str]:
    """Every email address in the text, normalised, in order of appearance."""
    cleaned, _ = strip_invisible(unicodedata.normalize("NFKC", text))
    return [m.group(0).casefold() for m in EMAIL_RE.finditer(cleaned)]


def hosts_in(text: str) -> set[str]:
    """Every host named in the text, whether in a URL, an address or on its own."""
    cleaned, _ = strip_invisible(unicodedata.normalize("NFKC", text))
    hosts = {host_of(u) for u in urls_in(cleaned)}
    hosts |= {m.group(0).casefold() for m in _BARE_HOST_RE.finditer(cleaned)}
    return hosts


def urls_in(text: str) -> list[str]:
    cleaned, _ = strip_invisible(unicodedata.normalize("NFKC", text))
    return [m.group(0) for m in URL_RE.finditer(cleaned)]


def host_of(url: str) -> str:
    """The host part of a URL, lowercased, without credentials or port.

    Taken by hand rather than with urlsplit so that a malformed URL still yields
    the authority the browser would use.
    """
    rest = url.split("://", 1)[-1]
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "@" in authority:  # https://user:pass@real-looking-host@evil.example
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        closing = authority.find("]")
        return authority[1:closing].casefold() if closing != -1 else authority.casefold()
    return authority.split(":", 1)[0].casefold()
