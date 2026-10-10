"""Secrets and Indian identifiers: it must find real ones and leave prose alone.

False positives are the thing that makes a guard get switched off, so the
negative cases matter as much as the positive ones.
"""

from __future__ import annotations

import pytest

from muffleguard.detectors.secrets import luhn_ok, redact, scan, shannon_entropy, verhoeff_ok


def kinds(text: str) -> set[str]:
    return {f.kind for f in scan(text)}


# Verhoeff-valid Aadhaar-shaped numbers, generated with the published algorithm.
VALID_AADHAAR = ["234123456783", "367598346783", "498273645126"]


@pytest.mark.parametrize("number", VALID_AADHAAR)
def test_valid_aadhaar_passes_verhoeff(number):
    assert verhoeff_ok(number)


def test_aadhaar_checksum_rejects_a_wrong_digit():
    broken = VALID_AADHAAR[0][:-1] + ("0" if VALID_AADHAAR[0][-1] != "0" else "1")
    assert not verhoeff_ok(broken)


def test_random_twelve_digits_are_not_reported_as_aadhaar():
    """The whole point of the checksum: an invoice number is not an identity."""
    assert "aadhaar" not in kinds("Order 123456789012 shipped on Tuesday.")


def test_aadhaar_found_with_spaces():
    assert "aadhaar" in kinds("Aadhaar: 2341 2345 6783")


def test_luhn_accepts_a_test_card_and_rejects_a_typo():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


def test_card_detected_only_when_the_checksum_holds():
    assert "card" in kinds("card 4111 1111 1111 1111")
    assert "card" not in kinds("card 4111 1111 1111 1112")


@pytest.mark.parametrize(
    "text,kind",
    [
        ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        # Assembled at run time: a live-key literal in the file would trip
        # GitHub push protection, which is right to flag it.
        ("sk_live_" + "51HxVnpKq9XmTbR4w2LzYdQ8e", "stripe_key"),
        ("AIzaSyA1234567890abcdefghijklmnopqrstuv", "google_api_key"),
        ("PAN ABCDE1234F on file", "pan"),
        ("pay to priya@okaxis now", "upi"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
    ],
)
def test_known_secret_shapes_are_found(text, kind):
    assert kind in kinds(text)


def test_plain_prose_has_no_findings():
    text = "Please find invoice INV-2291 for September, due 15 October, total Rs 48,500."
    assert scan(text) == []


def test_assigned_secret_needs_entropy():
    assert "assigned_secret" in kinds("API_KEY = 8f3Kd0zQmVx71PbWyRt4")
    assert "assigned_secret" not in kinds("password = aaaaaaaaaaaaaaaaaaaa")


def test_entropy_separates_a_key_from_a_word():
    assert shannon_entropy("8f3Kd0zQmVx71PbWyRt4") > shannon_entropy("aaaaaaaaaaaaaaaaaaaa")


def test_redaction_removes_the_value_and_keeps_the_sentence():
    text = "The key is AKIAIOSFODNN7EXAMPLE, use it today."
    clean, findings = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in clean
    assert "use it today" in clean
    assert findings and findings[0].masked.endswith("LE")


def test_masked_value_never_shows_the_middle():
    finding = scan("AKIAIOSFODNN7EXAMPLE")[0]
    assert "OSFODNN7" not in finding.masked


def test_overlapping_matches_are_reported_once():
    """An Aadhaar number must not also come back as a phone number."""
    found = scan("Aadhaar 2341 2345 6783")
    assert len(found) == 1
    assert found[0].kind == "aadhaar"


@pytest.mark.parametrize(
    "line",
    [
        "DB_PASSWORD=hunter2-correct-horse-battery",
        "SESSION_TOKEN=8f3Kd0zQmVx71PbWyRt4Lc9Ja2Nh",
        "GITHUB_TOKEN: 7Qm2xVr9Lb4TzHw6Ks1Fd8Np",
        "my_api_key = 8f3Kd0zQmVx71PbWyRt4",
    ],
)
def test_secrets_named_with_a_prefix_are_found(line):
    """DB_PASSWORD and SESSION_TOKEN are how real env files name them."""
    assert "assigned_secret" in kinds(line)


def test_an_empty_assignment_does_not_borrow_the_next_line():
    """A blank SECRET= is not a secret, whatever follows it.

    The value pattern allowed any whitespace after the "=", including a
    newline, so an empty assignment ran on and claimed the next variable's
    name as its value. A .env.example full of blank placeholders reported one.
    """
    blanks = "GOOGLE_CLIENT_ID=\nGOOGLE_CLIENT_SECRET=\nGOOGLE_REDIRECT_URI=\n"
    assert "assigned_secret" not in kinds(blanks)

    # A real one on a single line is still caught.
    assert "assigned_secret" in kinds("GOOGLE_CLIENT_SECRET=7Qm2xVr9Lb4TzHw6Ks1Fd8Np")
