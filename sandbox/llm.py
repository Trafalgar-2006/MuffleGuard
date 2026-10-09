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
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

# Two caches, on purpose. The demo fixtures are committed, because the
# offline demo is served from them and a reviewer should be able to read
# exactly what the model was recorded saying. Everything else a run happens
# to produce stays out of git, so a response from a real mailbox can never
# be staged by accident.
DEMO_CACHE = Path(__file__).resolve().parent.parent / "demo_cache"
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


# Every setting the app reads. A deployment has no .env file, so anything
# missing from this list can only be configured locally: leaving DEMO_PASSCODE
# out of it once meant the live demo ran with its API unprotected while the
# platform showed the variable as set.
SETTINGS = (
    "LLM_API_KEY",
    "LLM_BASE_URL",
    "LLM_MODEL",
    "LLM_MODEL_STRONG",
    "DEMO_PASSCODE",
    "DEMO_TAMPER",
    "DEMO_DAILY_RUNS",
    "LLM_CACHE",
    "TRUST_PROXY",
)


def load_env(path: Path | None = None) -> dict:
    """Settings from the environment, falling back to .env. Never logged.

    The environment wins, because that is how a deployment configures itself.
    """
    env_path = path or Path(__file__).resolve().parent.parent / ".env"
    values = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    for key in SETTINGS:
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values


class LLM:
    """One chat completion call with optional response caching."""

    def __init__(
        self,
        model: str | None = None,
        env: dict | None = None,
        use_cache: bool | None = None,
        replay: bool = False,
        on_live_call: Callable[[], bool] | None = None,
    ):
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
        # Live prompts can contain private data, so scratch caching is opt-in.
        if use_cache is None:
            use_cache = self.env.get("LLM_CACHE", "").strip() == "1"
        self.use_cache = use_cache
        # replay serves only what is already cached and never calls out. A miss
        # is an error rather than a stand-in answer: a demo that invented the
        # model's reply would be showing a story, not a result.
        self.replay = replay
        self.on_live_call = on_live_call

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
        # Shipped synthetic demo fixtures are safe to read even when caching is
        # disabled; only the per-machine cache may contain live user data.
        fixture = DEMO_CACHE / f"{key}.json"
        if fixture.exists():
            return json.loads(fixture.read_text(encoding="utf-8"))
        if self.use_cache and cached.exists():
            return json.loads(cached.read_text(encoding="utf-8"))

        if self.replay:
            raise LLMError(
                "This demo has no model key, so it can only replay the request it "
                "ships with. Press Run both without changing the request, or run it "
                "locally with your own key to try others."
            )

        api_key = self.env.get("LLM_API_KEY")
        if not api_key:
            raise LLMError("LLM_API_KEY is not set; copy .env.example to .env and fill it in")
        if self.on_live_call is not None and not self.on_live_call():
            raise LLMError("the daily live model call limit has been reached")

        import httpx

        response = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=body,
            timeout=180,  # some free providers are slow to first token
        )
        if response.status_code != 200:
            # A provider error body can echo credentials or private prompt data.
            raise LLMError(f"{self.model}: HTTP {response.status_code}")
        data = response.json()
        if self.use_cache:
            CACHE_DIR.mkdir(exist_ok=True)
            # Written beside the target and moved into place, so parallel
            # runs cannot leave a half-written file the demo later replays.
            temporary = cached.with_suffix(f".{os.getpid()}-{threading.get_ident()}.tmp")
            temporary.write_text(json.dumps(data), encoding="utf-8")
            os.replace(temporary, cached)
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
