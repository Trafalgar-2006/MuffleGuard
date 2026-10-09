"""Re-record the demo's model responses after the tool schema changes.

The cache is keyed by the exact request body, and that body includes the tool
schema. Changing the schema therefore orphans every cached response, which
breaks the offline demo and the deployed site rather than any test. Run this
once after such a change, with a key in .env, and commit the result.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from muffleguard.guard import Guard  # noqa: E402
from sandbox.agent import run_agent  # noqa: E402
from sandbox import llm as llm_module  # noqa: E402
from sandbox.llm import LLM  # noqa: E402
from sandbox.tools import SPECS  # noqa: E402
from sandbox.world import DEMO_REQUEST, World  # noqa: E402

# Every combination the demo and the tests actually replay.
COMBINATIONS = [
    ("unguarded", None, None),
    ("guarded, muffling on", True, None),
    ("guarded, muffling off", False, None),
]


def main() -> int:
    # Record into the committed fixtures, not the scratch cache, or the
    # demo works on this machine and nowhere else.
    llm_module.DEMO_CACHE.mkdir(exist_ok=True)
    llm_module.CACHE_DIR = llm_module.DEMO_CACHE
    for name, muffle, detector in COMBINATIONS:
        guard = (
            None
            if muffle is None
            else Guard(tools=SPECS, detector=detector, muffle=muffle)
        )
        result = run_agent(DEMO_REQUEST, world=World(), guard=guard, llm=LLM())
        status = "error: " + result.error if result.error else (
            "breached" if result.breached else "held"
        )
        print(f"  {name:24s} {status}")
    print("recorded into demo_cache; commit it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
