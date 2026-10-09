"""Scan the tracked files for anything credential-shaped, using our own detector.

Dogfooding: the thing that stops the agent leaking a key is the same thing that
stops us committing one. It runs in CI, so a key pasted into a file fails the
build rather than reaching a public repository.

The sandbox fixtures are deliberately secret-shaped, so they are listed here by
name rather than by pattern. Adding a file to that list is a decision someone
makes on purpose, which is the point.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from muffleguard.detectors.secrets import scan  # noqa: E402

# Files whose whole purpose is to contain convincing fake credentials.
FIXTURES = {
    "sandbox/world.py",  # the private file the demo agent is tricked into sending
    "tests/test_secrets.py",  # the detector's own test vectors
    "tests/test_redteam.py",  # red-team payloads
    "tests/test_policy.py",
    "tests/test_attacks.py",
    "tests/test_web.py",
    "evaluation/suite.py",
    "MuffleGuard_SECURITY_REVIEW.md",
}

# Kinds that say "a person's identity" rather than "a credential". The sandbox
# is full of fake ones and a phone-shaped number is too common to gate a build.
IGNORED_KINDS = {"phone_in", "aadhaar", "pan", "card", "upi"}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [line for line in out.splitlines() if line]


def main() -> int:
    findings: list[tuple[str, str, str]] = []
    for name in tracked_files():
        if name in FIXTURES:
            continue
        path = ROOT / name
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable: nothing for a text scanner to do
        for finding in scan(text):
            if finding.kind in IGNORED_KINDS:
                continue
            # The documentation example key is AWS's own published placeholder.
            if "EXAMPLE" in finding.value:
                continue
            findings.append((name, finding.kind, finding.masked))

    if findings:
        print("Credential-shaped strings in tracked files:")
        for name, kind, masked in findings:
            print(f"  {name}: {kind} {masked}")
        print("\nIf one is a deliberate fixture, add its file to FIXTURES in this script.")
        return 1

    print(f"{len(tracked_files())} tracked files scanned, nothing credential-shaped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
