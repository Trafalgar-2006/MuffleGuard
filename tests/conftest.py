"""Shared fixtures, and a fake model that plays a scripted attack.

The attacks must be reproducible, free and runnable with the network off, so the
end-to-end tests drive the agent with a model that has already decided to obey
the injection. That is the honest worst case: it tests the guard, not the
model's good judgement.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from muffleguard.guard import Guard  # noqa: E402
from sandbox.tools import SPECS  # noqa: E402
from sandbox.world import World  # noqa: E402


class ScriptedLLM:
    """Replays a fixed list of turns, ignoring what the agent sends back."""

    def __init__(self, turns: list[dict]):
        self.turns = list(turns)
        self.seen: list[list] = []

    def complete(self, messages, tools=None, temperature: float = 0.0) -> dict:
        self.seen.append(list(messages))
        turn = self.turns.pop(0) if self.turns else {"content": "Done."}
        return {"choices": [{"message": turn}]}

    @staticmethod
    def message_of(response: dict) -> dict:
        return response["choices"][0]["message"]


def tool_turn(name: str, args: dict, call_id: str = "c1") -> dict:
    return {
        "content": None,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(args)},
            }
        ],
    }


@pytest.fixture
def world() -> World:
    return World()


@pytest.fixture
def guard() -> Guard:
    """A guard with the detectors off: the policy engine alone."""
    return Guard(tools=SPECS, detector=None)
