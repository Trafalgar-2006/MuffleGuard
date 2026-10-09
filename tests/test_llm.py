"""The provider boundary must not leak keys through config or error messages."""

from __future__ import annotations

import json
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
    """LLM_CACHE=0 prevents live responses from being written to disk."""
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


@pytest.mark.parametrize("cache_setting", [None, "", "0", "false"])
def test_response_caching_requires_explicit_opt_in(monkeypatch, tmp_path, cache_setting):
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
    env = {"LLM_API_KEY": "test-key", "LLM_BASE_URL": "https://provider.example/api"}
    if cache_setting is not None:
        env["LLM_CACHE"] = cache_setting
    llm = LLM(env=env)

    llm.complete([Message("user", "hello")])

    assert list(tmp_path.iterdir()) == []


def test_response_caching_can_be_opted_in(monkeypatch, tmp_path):
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
    llm = LLM(env={
        "LLM_API_KEY": "test-key",
        "LLM_BASE_URL": "https://provider.example/api",
        "LLM_CACHE": "1",
    })

    llm.complete([Message("user", "hello")])

    assert list(tmp_path.iterdir())


def test_replay_reads_demo_fixture_when_scratch_caching_is_off(monkeypatch, tmp_path):
    from sandbox import llm as llm_module

    demo_cache = tmp_path / "demo"
    scratch_cache = tmp_path / "scratch"
    demo_cache.mkdir()
    monkeypatch.setattr(llm_module, "DEMO_CACHE", demo_cache)
    monkeypatch.setattr(llm_module, "CACHE_DIR", scratch_cache)
    llm = LLM(env={"LLM_CACHE": "0"}, replay=True)
    messages = [Message("user", "the supplied demo request")]
    body = {
        "model": llm.model,
        "messages": [message.wire() for message in messages],
        "temperature": 0.0,
    }
    expected = {"choices": [{"message": {"content": "synthetic fixture"}}]}
    (demo_cache / f"{llm._key(body)}.json").write_text(json.dumps(expected), encoding="utf-8")
    monkeypatch.setitem(
        sys.modules,
        "httpx",
        SimpleNamespace(post=lambda *args, **kwargs: pytest.fail("replay must not call the provider")),
    )

    assert llm.complete(messages) == expected
    assert not scratch_cache.exists()


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
