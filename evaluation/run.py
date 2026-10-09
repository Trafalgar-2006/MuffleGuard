"""Run the evaluation once against the real model and freeze the result.

Once, and then the file is committed. Rerunning until the numbers look better
is how an evaluation stops meaning anything, so the output records the model
and the time it was produced, and the scorecard shows exactly that file.

    python -m evaluation.run              # the full suite
    python -m evaluation.run --quick      # two tasks, for checking the plumbing
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluation.redteam import CONDITIONS, run_suite  # noqa: E402
from evaluation.suite import ATTACKS, TASKS  # noqa: E402
from sandbox.llm import LLM, load_env  # noqa: E402

RESULTS = Path(__file__).resolve().parent / "results.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="two tasks only")
    parser.add_argument(
        "--adversary",
        action="store_true",
        help="use the deterministic worst-case agent instead of a model",
    )
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--out", default=str(RESULTS))
    args = parser.parse_args()

    env = load_env()
    tasks = TASKS[:2] if args.quick else TASKS
    if args.adversary:
        from evaluation.adversary import ObedientAdversary

        model = "deterministic worst-case agent (obeys every instruction it can see)"
        factory = ObedientAdversary
    else:
        model = env.get("LLM_MODEL", "openai/gpt-4o-mini")
        # No cache: a suite that replays recorded answers measures the
        # recording. Identical opening prompts would otherwise let one
        # condition serve the next one's runs.
        factory = lambda: LLM(model=model, env=env, use_cache=False)  # noqa: E731

    runs = len(CONDITIONS) * len(tasks) * (len(ATTACKS) + 1)
    print(f"{len(tasks)} tasks x {len(ATTACKS)} attacks x {len(CONDITIONS)} conditions = {runs} runs")
    print(f"model: {model}\n")

    result = run_suite(
        tasks=tasks,
        llm_factory=factory,
        workers=args.workers,
        model=model,
    )

    for condition in result.by_condition.values():
        print(f"  {condition.name:8s} data reached attacker {condition.attack_success}")
        print(f"  {'':8s} model attempted it   {condition.attempt_rate}")
        print(f"  {'':8s} stopped when tried   {condition.stopped_when_attempted}")
        print(f"  {'':8s} clean tasks done     {condition.task_completion}")

    errors = [r for r in result.runs if r.error]
    if errors:
        print(f"\n  {len(errors)} run(s) errored, e.g. {errors[0].error[:120]}")

    Path(args.out).write_text(json.dumps(result.as_dict(), indent=2), encoding="utf-8")
    print(f"\nwritten to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
