"""The provider boundary must not leak keys through config or error messages."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from sandbox.llm import LLM, LLMError, Message


def test_client_rejects_plain_http_before_sending_the_api_key():
    with pytest.raises(LLMError, match="HTTPS"):
        LLM(
            env={"LLM_API_KEY": "test-key", "LLM_BASE_URL": "http://provider.example/api"},
            use_cache=False,
        )


def test_http_error_body_cannot_echo_the_api_key(monkeypatch):
    key = "test-key-that-must-not-appear"
    monkeypatch.setitem(
        sys.modules,
        "httpx",
        SimpleNamespace(post=lambda *args, **kwargs: SimpleNamespace(
            status_code=401, text=f"invalid token: {key}"
        )),
    )
    llm = LLM(
        env={"LLM_API_KEY": key, "LLM_BASE_URL": "https://provider.example/api"},
        use_cache=False,
    )

    with pytest.raises(LLMError) as error:
        llm.complete([Message("user", "hello")])

    assert key not in str(error.value)


def test_response_caching_can_be_turned_off(monkeypatch, tmp_path):
    """The cache is on by default: the offline demo is served from it, and the
    recorded exchanges are the synthetic sandbox. Writing model responses to
    disk is still the caller's call, so LLM_CACHE=0 disables it.
    """
    from sandbox import llm as llm_module

    monkeypatch.setattr(llm_module, "CACHE_DIR", tmp_path)
    monkeypatch.setitem(
        sys.modules,
        "httpx",
        SimpleNamespace(post=lambda *args, **kwargs: SimpleNamespace(
            status_code=200, json=lambda: {"choices": []}
        )),
    )
    llm = LLM(env={
        "LLM_API_KEY": "test-key",
        "LLM_BASE_URL": "https://provider.example/api",
        "LLM_CACHE": "0",
    })

    llm.complete([Message("user", "private input")])

    assert list(tmp_path.iterdir()) == []


def test_the_cache_is_on_by_default(monkeypatch, tmp_path):
    """The offline demo depends on it, so the default must not drift off."""
    from sandbox import llm as llm_module

    monkeypatch.setattr(llm_module, "CACHE_DIR", tmp_path)
    monkeypatch.setitem(
        sys.modules,
        "httpx",
        SimpleNamespace(post=lambda *args, **kwargs: SimpleNamespace(
            status_code=200,
            json=lambda: {"choices": [{"message": {"content": "ok"}}]},
        )),
    )
    llm = LLM(env={"LLM_API_KEY": "test-key", "LLM_BASE_URL": "https://provider.example/api"})

    llm.complete([Message("user", "hello")])

    assert list(tmp_path.iterdir()), "a response should have been recorded"


def test_the_committed_fixtures_are_actually_committed():
    """The offline demo is served from these, so they must be in the repo.

    They were once written into a git-ignored directory, so every test passed
    on the machine that recorded them and seven failed on a fresh clone.
    """
    import subprocess

    from sandbox.llm import DEMO_CACHE

    recorded = sorted(p.name for p in DEMO_CACHE.glob("*.json"))
    assert recorded, "no demo fixtures recorded; run tools/warm_cache.py"

    tracked = subprocess.run(
        ["git", "ls-files", "demo_cache"],
        capture_output=True, text=True, cwd=DEMO_CACHE.parent,
    ).stdout.split()
    tracked_names = sorted(name.split("/")[-1] for name in tracked)
    assert tracked_names == recorded, "demo fixtures exist but are not tracked by git"
