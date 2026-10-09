"""An OpenAI-compatible chat client with a cache on disk.

Any provider that speaks the OpenAI chat API works: OpenRouter, OpenAI, Groq.
Only the base URL and the model change, which is why they live in `.env` and
not in the code.

Every response is cached by the hash of the request, so a red-team run of
several hundred attacks is paid for once and then replays for free, and a demo
plays back identically with the Wi-Fi off.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

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

    def __init__(
        self,
        model: str | None = None,
        env: dict | None = None,
        use_cache: bool = True,
        replay: bool = False,
    ):
        self.env = env or load_env()
        self.model = model or self.env.get("LLM_MODEL", "openai/gpt-4o-mini")
        self.base_url = self.env.get("LLM_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
        self.use_cache = use_cache
        # replay serves only what is already cached and never calls out. A miss
        # is an error rather than a stand-in answer: a demo that invented the
        # model's reply would be showing a story, not a result.
        self.replay = replay
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

        if self.replay:
            raise LLMError(
                "no cached response for this request. Set LLM_API_KEY to run it live, "
                "or use the request the demo ships with."
            )

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
            # The body can echo the request; never include the key in the error.
            raise LLMError(f"{self.model}: HTTP {response.status_code} {response.text[:200]}")
        data = response.json()
        self.calls += 1
        if self.use_cache:
            CACHE_DIR.mkdir(exist_ok=True)
            cached.write_text(json.dumps(data), encoding="utf-8")
        return data

    @staticmethod
    def message_of(response: dict) -> dict:
        return response["choices"][0]["message"]
