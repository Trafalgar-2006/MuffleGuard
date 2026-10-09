"""Rates with the uncertainty that comes from measuring them a finite number of times.

A score from 64 runs is a range, and a judge is right to ask how wide. The
Wilson interval is used rather than the textbook normal approximation because
these rates sit near 0 and 1, where the normal one gives bounds below zero and
above one, and claims a certainty that 64 runs cannot support.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# 1.96 standard deviations covers 95% of a normal distribution.
Z95 = 1.959963984540054


def wilson(successes: int, total: int, z: float = Z95) -> tuple[float, float]:
    """The Wilson score interval for a proportion, clamped to [0, 1].

    With no observations the honest answer is the whole range, not an error.
    """
    if total <= 0:
        return 0.0, 1.0

    phat = successes / total
    denominator = 1 + z * z / total
    centre = (phat + z * z / (2 * total)) / denominator
    spread = (
        z
        / denominator
        * math.sqrt(phat * (1 - phat) / total + z * z / (4 * total * total))
    )
    low, high = max(0.0, centre - spread), min(1.0, centre + spread)
    # At no successes the lower bound is exactly 0, and at all successes the
    # upper bound is exactly 1. Floating point leaves each a hair short, which
    # a scorecard would print as 99.99999%.
    if successes == 0:
        low = 0.0
    if successes == total:
        high = 1.0
    return low, high


@dataclass(frozen=True)
class Rate:
    """How often something happened, and how sure we can be about it."""

    successes: int
    total: int

    @property
    def value(self) -> float:
        return self.successes / self.total if self.total else 0.0

    @property
    def interval(self) -> tuple[float, float]:
        return wilson(self.successes, self.total)

    @property
    def percent(self) -> str:
        low, high = self.interval
        return f"{self.value:.0%} ({low:.0%}-{high:.0%})"

    def as_dict(self) -> dict:
        low, high = self.interval
        return {
            "successes": self.successes,
            "total": self.total,
            "value": self.value,
            "low": low,
            "high": high,
        }

    def __str__(self) -> str:
        return f"{self.successes}/{self.total} = {self.percent}"
