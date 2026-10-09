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


def test_response_cache_is_off_by_default(monkeypatch, tmp_path):
    from sandbox import llm as llm_module

    monkeypatch.setattr(llm_module, "CACHE_DIR", tmp_path)
    monkeypatch.setitem(
        sys.modules,
        "httpx",
        SimpleNamespace(post=lambda *args, **kwargs: SimpleNamespace(
            status_code=200, json=lambda: {"choices": []}
        )),
    )
    llm = LLM(env={"LLM_API_KEY": "test-key", "LLM_BASE_URL": "https://provider.example/api"})

    llm.complete([Message("user", "private input")])

    assert list(tmp_path.iterdir()) == []
