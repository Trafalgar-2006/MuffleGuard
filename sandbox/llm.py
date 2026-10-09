"""An OpenAI-compatible chat client with a cache on disk.

Any provider that speaks the OpenAI chat API works: OpenRouter, OpenAI, Groq.
Only the base URL and the model change, which is why they live in `.env` and
not in the code.

When enabled, responses are cached by the hash of the request, so the demo can
replay its synthetic runs with the Wi-Fi off. Caching is opt-in for normal use.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

CACHE_DIR = Path(__file__).resolve().parent.parent / ".llm_cache"


class LLMError(RuntimeError):
    pass


@dataclass
class Message:
    role: str
    content: str | None = None
    tool_calls: list | None = None
    tool_call_id: str | None = None
    name: str | None = None

    def wire(self) -> dict:
        d: dict = {"role": self.role}
        if self.content is not None:
            d["content"] = self.content
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        if self.name:
            d["name"] = self.name
        return d


def load_env(path: Path | None = None) -> dict:
    """Read .env without a dependency, and never log what it holds."""
    env_path = path or Path(__file__).resolve().parent.parent / ".env"
    values = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    for key in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL", "LLM_MODEL_STRONG"):
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values


class LLM:
    """One chat completion call, cached."""

    def __init__(self, model: str | None = None, env: dict | None = None, use_cache: bool = False):
        self.env = env or load_env()
        self.model = model or self.env.get("LLM_MODEL", "openai/gpt-4o-mini")
        self.base_url = self.env.get("LLM_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
        try:
            endpoint = urlsplit(self.base_url)
            valid_endpoint = (
                endpoint.scheme == "https"
                and bool(endpoint.hostname)
                and endpoint.username is None
                and endpoint.password is None
                and not endpoint.query
                and not endpoint.fragment
            )
        except ValueError:
            valid_endpoint = False
        if not valid_endpoint:
            raise LLMError("LLM_BASE_URL must be an HTTPS URL without embedded credentials")
        self.use_cache = use_cache
        self.calls = 0
        self.cache_hits = 0

    def _key(self, body: dict) -> str:
        blob = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:32]

    def complete(self, messages: list[Message], tools: list | None = None, temperature: float = 0.0) -> dict:
        body = {
            "model": self.model,
            "messages": [m.wire() for m in messages],
            "temperature": temperature,
        }
        if tools:
            body["tools"] = tools

        key = self._key(body)
        cached = CACHE_DIR / f"{key}.json"
        if self.use_cache and cached.exists():
            self.cache_hits += 1
            return json.loads(cached.read_text(encoding="utf-8"))

        api_key = self.env.get("LLM_API_KEY")
        if not api_key:
            raise LLMError("LLM_API_KEY is not set; copy .env.example to .env and fill it in")

        import httpx

        response = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=body,
            timeout=120,
        )
        if response.status_code != 200:
            # A provider error body can echo credentials or private prompt data.
            raise LLMError(f"{self.model}: HTTP {response.status_code}")
        data = response.json()
        self.calls += 1
        if self.use_cache:
            CACHE_DIR.mkdir(exist_ok=True)
            cached.write_text(json.dumps(data), encoding="utf-8")
        return data

    @staticmethod
    def message_of(response: dict) -> dict:
        choices = response.get("choices") if isinstance(response, dict) else None
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise LLMError("provider returned an invalid chat response")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise LLMError("provider returned an invalid chat response")
        content = message.get("content")
        tool_calls = message.get("tool_calls")
        if content is not None and not isinstance(content, str):
            raise LLMError("provider returned an invalid chat response")
        if tool_calls is not None and not isinstance(tool_calls, list):
            raise LLMError("provider returned an invalid chat response")
        return message
