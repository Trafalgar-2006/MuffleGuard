from __future__ import annotations

from tools import check_secrets


def _scan_fixture(monkeypatch, tmp_path, text, capsys):
    target = tmp_path / "tests" / "test_web.py"
    target.parent.mkdir()
    target.write_text(text, encoding="utf-8")
    monkeypatch.setattr(check_secrets, "ROOT", tmp_path)
    monkeypatch.setattr(check_secrets, "tracked_files", lambda: ["tests/test_web.py"])
    result = check_secrets.main()
    return result, capsys.readouterr().out


def test_scanner_detects_a_key_in_a_test_fixture_file(monkeypatch, tmp_path, capsys):
    fake_live_key = "sk-proj-" + "A" * 40
    result, output = _scan_fixture(
        monkeypatch,
        tmp_path,
        f'LLM_API_KEY = "{fake_live_key}"\n',
        capsys,
    )

    assert result == 1
    assert "openai_key" in output


def test_scanner_does_not_treat_every_example_substring_as_a_placeholder(
    monkeypatch, tmp_path, capsys
):
    fake_key = "sk-proj-" + "EXAMPLE" + "12345678901234567890"
    result, output = _scan_fixture(
        monkeypatch,
        tmp_path,
        f'LLM_API_KEY = "{fake_key}"\n',
        capsys,
    )

    assert result == 1
    assert "openai_key" in output


def test_scanner_allows_only_the_known_test_key(monkeypatch, tmp_path, capsys):
    known_fake_key = "sk-test-not-" + "used-offline"
    result, output = _scan_fixture(
        monkeypatch,
        tmp_path,
        f'LLM_API_KEY = "{known_fake_key}"\n',
        capsys,
    )

    assert result == 0
    assert "nothing credential-shaped" in output


def test_scanner_does_not_ignore_a_card_number_in_a_fixture_file(monkeypatch, tmp_path, capsys):
    fake_card = "41111111" + "11111111"
    result, output = _scan_fixture(
        monkeypatch,
        tmp_path,
        f'CARD_NUMBER = "{fake_card}"\n',
        capsys,
    )

    assert result == 1
    assert "card" in output


def test_an_svg_path_is_not_reported_as_a_card_number(monkeypatch, tmp_path, capsys):
    """The drawings tripped the card rule: strip the separators from a path's
    coordinates and some runs are Luhn-valid. They are drawing instructions."""
    path = 'M60 15 C80 15 92 28 92 44 C92 54 86 60 86 60 C86 40 76 33 60 33 Z'
    result, output = _scan_fixture(
        monkeypatch, tmp_path, f'<svg><path d="{path}"></path></svg>\n', capsys
    )

    assert result == 0, output


def test_a_key_beside_an_svg_path_is_still_caught(monkeypatch, tmp_path, capsys):
    """The exclusion is the geometry attribute only, not the file around it."""
    result, output = _scan_fixture(
        monkeypatch,
        tmp_path,
        '<svg><path d="M60 15 C80 15 92 28 92 44 Z"></path></svg>\n'
        'KEY = "AKIAIOSFODNN' + '7EXAMPLE"\n',
        capsys,
    )

    assert result == 1
    assert "aws" in output.lower()


NUMBERS = "var t=[9478123456,0.9999619230641713];"
AWS_KEY = "var e='AKIAIOSFODNN7EXAMPLE';"


def _scan_at(monkeypatch, tmp_path, rel, text, capsys):
    """Scan one file at a chosen path, so the vendored exemption can be tested
    on the path it keys off."""
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    monkeypatch.setattr(check_secrets, "ROOT", tmp_path)
    monkeypatch.setattr(check_secrets, "tracked_files", lambda: [rel])
    return check_secrets.main(), capsys.readouterr().out


def test_numeric_pii_in_a_vendored_bundle_is_not_a_finding(monkeypatch, tmp_path, capsys):
    """three.min.js carries a number that reads as an Indian phone number. A
    minified library is a wall of numeric literals and some of them land on a
    checksum by chance."""
    result, output = _scan_at(
        monkeypatch, tmp_path, "site/assets/vendor/three.min.js", NUMBERS, capsys
    )

    assert result == 0, output


def test_the_same_number_outside_vendor_is_still_a_finding(monkeypatch, tmp_path, capsys):
    """The exemption is the vendor directory, not the pattern."""
    result, output = _scan_at(
        monkeypatch, tmp_path, "site/assets/motion.js", NUMBERS, capsys
    )

    assert result == 1
    assert "phone" in output.lower()


def test_a_credential_in_a_vendored_bundle_is_still_caught(monkeypatch, tmp_path, capsys):
    """A key pasted into a vendored file would be ours, so that half of the
    gate stays on."""
    result, output = _scan_at(
        monkeypatch, tmp_path, "site/assets/vendor/three.min.js", AWS_KEY, capsys
    )

    assert result == 1
    assert "aws" in output.lower()
