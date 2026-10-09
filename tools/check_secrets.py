"""Scan the tracked files for anything credential-shaped, using our own detector.

Dogfooding: the thing that stops the agent leaking a key is the same thing that
stops us committing one. It runs in CI, so a key pasted into a file fails the
build rather than reaching a public repository.

The sandbox fixtures contain a few deliberate fake credentials. Only those
exact values are exempt; the rest of each file is still scanned.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from muffleguard.detectors.secrets import scan  # noqa: E402

# Exact synthetic values embedded in fixtures and tests. Split recognizable
# prefixes in the source so this scanner does not report its own allowlist.
AWS_TEST_KEY = "AKIAIOSFODNN" + "7EXAMPLE"
FIXTURE_VALUES = {
    "sandbox/world.py": {
        AWS_TEST_KEY,
        "hunter2-correct-horse-battery",
        "8f3Kd0zQmVx71" + "PbWyRt4Lc9Ja2Nh",
        "ABCDE" + "1234F",
        "FGHIJ" + "5678K",
        "2341 2345 " + "6783",
        "3675 9834 " + "6783",
    },
    "tests/test_secrets.py": {
        AWS_TEST_KEY,
        "AIzaSyA1234567890abcdefghijklmnop" + "qrstuv",
        "-----BEGIN RSA " + "PRIVATE KEY-----",
        "hunter2-correct-horse-battery",
        "8f3Kd0zQmVx71" + "PbWyRt4Lc9Ja2Nh",
        "8f3Kd0zQmVx71" + "PbWyRt4",
        "7Qm2xVr9Lb4TzHw6Ks1Fd8Np",
        "ABCDE" + "1234F",
        "priya@" + "okaxis",
        "2341 2345 " + "6783",
        "2341" + "23456783",
        "36759834" + "6783",
        "49827364" + "5126",
        "4111 1111 1111 " + "1111",
        "41111111" + "11111111",
    },
    "tests/test_redteam.py": {
        AWS_TEST_KEY,
        "hunter2-correct-horse-battery",
    },
    "tests/test_attacks.py": {
        AWS_TEST_KEY,
        "hunter2-correct-horse-battery",
        "8f3Kd0zQmVx71" + "PbWyRt4Lc9Ja2Nh",
        "ABCDE" + "1234F",
    },
    "tests/test_guard.py": {AWS_TEST_KEY},
    "tests/test_policy.py": {AWS_TEST_KEY},
    "tests/test_redteam_runner.py": {AWS_TEST_KEY},
    "tests/test_web.py": {"sk-test-not-" + "used-offline"},
    "evaluation/stats.py": {"959963984" + "540054"},
}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [line for line in out.splitlines() if line]


def _looks_utf16(raw: bytes) -> bool:
    """UTF-16 text: a BOM, or ASCII bytes alternating with NULs."""
    if raw[:2] in (bytes([255, 254]), bytes([254, 255])):
        return True
    head = raw[:512]
    return len(head) > 8 and head[1::2].count(0) > len(head) // 3


def _without_vector_geometry(text: str) -> str:
    """Blank the coordinate payload of inline SVG before scanning.

    The illustrations on the site are inline SVG, and a path's `d` attribute is
    a long run of space-separated numbers. Strip the separators, as a card
    detector must, and some of those runs are Luhn-valid: the scanner reported
    the drawings as payment cards. The digits are drawing instructions, not a
    number anyone could pay with, so they are removed here rather than by
    loosening the detector the guard itself uses.

    Narrow on purpose: only geometry attributes, and only their contents. A
    credential is not digits-only, so nothing credential-shaped hides in one.
    """
    return re.sub(
        r'\b(d|points|viewBox|transform|stroke-dasharray)="[0-9eE,.\s+\-A-Za-z()%]*"',
        r'\1=""',
        text,
    )


def main() -> int:
    findings: list[tuple[str, str, str]] = []
    skipped_binary = 0
    for name in tracked_files():
        path = ROOT / name
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        # A file Notepad saved as "Unicode" is UTF-16, and decoding it strictly
        # as UTF-8 used to skip it silently: a real key in such a file passed
        # the gate. Decode what we can instead of giving up on the file.
        # A real binary is not text and scanning it as text invents findings:
        # random bytes produce Luhn-valid digit runs. Skipped on purpose, and
        # counted, because a file skipped silently is how a key gets through.
        if 0 in raw[:1024] and not _looks_utf16(raw):
            skipped_binary += 1
            continue
        text = raw.decode("utf-8", errors="ignore")
        if _looks_utf16(raw):
            text += raw.decode("utf-16", errors="ignore")
        text = _without_vector_geometry(text)
        for finding in scan(text):
            if finding.value in FIXTURE_VALUES.get(name, set()):
                continue
            findings.append((name, finding.kind, finding.masked))

    if findings:
        print("Credential-shaped strings in tracked files:")
        for name, kind, masked in findings:
            print(f"  {name}: {kind} {masked}")
        print("\nIf one is a deliberate fixture, allow its exact synthetic value in FIXTURE_VALUES.")
        return 1

    print(
        f"{len(tracked_files()) - skipped_binary} tracked text files scanned, "
        f"nothing credential-shaped ({skipped_binary} binary skipped)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
