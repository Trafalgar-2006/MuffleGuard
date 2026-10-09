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
