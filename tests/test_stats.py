"""Confidence intervals for the rates the scorecard reports.

A rate from 64 runs is not a number, it is a range, and saying "0% attack
success" from a handful of runs claims more than the runs support. The expected
values below are the published Wilson figures, not this code's own output.
"""

from __future__ import annotations

import pytest

from evaluation.stats import Rate, wilson


def test_wilson_matches_the_published_interval_for_half_of_ten():
    """p=0.5, n=10, 95%: the textbook answer is (0.2366, 0.7634)."""
    low, high = wilson(5, 10)
    assert low == pytest.approx(0.2366, abs=5e-4)
    assert high == pytest.approx(0.7634, abs=5e-4)


def test_wilson_never_goes_below_zero_at_zero_successes():
    """Zero out of ten is not "0%, certainly": the upper bound is near 28%."""
    low, high = wilson(0, 10)
    assert low == 0.0
    assert high == pytest.approx(0.2775, abs=5e-4)


def test_wilson_never_goes_above_one_at_every_success():
    low, high = wilson(10, 10)
    assert low == pytest.approx(0.7225, abs=5e-4)
    assert high == 1.0


def test_more_runs_narrow_the_interval():
    narrow = wilson(50, 100)
    wide = wilson(5, 10)
    assert (narrow[1] - narrow[0]) < (wide[1] - wide[0])


def test_no_runs_is_the_whole_range_not_a_crash():
    assert wilson(0, 0) == (0.0, 1.0)


def test_a_rate_carries_its_interval_and_prints_honestly():
    rate = Rate(successes=1, total=64)
    assert rate.value == pytest.approx(1 / 64)
    low, high = rate.interval
    assert low < rate.value < high
    assert "1/64" in str(rate)
