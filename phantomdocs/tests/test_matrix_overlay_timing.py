"""Unprivileged boundary checks for the integrated trial's actual budget guard."""

import math
import runpy
from pathlib import Path

import pytest

SOURCE = Path(__file__).with_name("test_matrix_overlay_integrated_systemd.py")


@pytest.fixture
def budget():
    # Loading the module defines its trial but does not execute systemd or I/O.
    return runpy.run_path(str(SOURCE), run_name="overlay_timing_unit_test")[
        "assert_contention_budget"
    ]


@pytest.mark.parametrize("elapsed", [55.0, 55.001, math.nextafter(65.0, 0.0)])
def test_accepts_contention_only_inside_55_65(budget, elapsed):
    budget(elapsed)


@pytest.mark.parametrize(
    "elapsed",
    [
        0.0,
        math.nextafter(55.0, 0.0),
        65.0,
        65.001,
        79.999,
        80.0,
        math.inf,
        math.nan,
    ],
)
def test_refuses_early_or_over_budget_completion(budget, elapsed):
    with pytest.raises(AssertionError, match="finish in"):
        budget(elapsed)
