# Copyright 2026 UCID Foundation
#
# Licensed under the EUPL, Version 1.2 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Sensitivity analysis tools for UCID scoring.

This module provides functions for analyzing how scoring results
vary with changes in input parameters.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class SensitivityResult:
    """Result of a sensitivity analysis.

    Attributes:
        baseline: The baseline result with original parameters.
        variations: Dictionary mapping parameter names to lists of results.
        parameters: The parameter ranges that were tested.
    """

    baseline: Any
    variations: dict[str, list[Any]]
    parameters: dict[str, list[Any]]


def analyze_sensitivity(
    func: Callable[..., Any],
    base_params: dict[str, Any],
    param_ranges: dict[str, list[Any]],
) -> SensitivityResult:
    """Perform one-at-a-time sensitivity analysis.

    Evaluates how the output of a function varies when each parameter
    is modified independently while holding others constant.

    Args:
        func: Function to analyze. Should accept keyword arguments.
        base_params: Baseline parameter values.
        param_ranges: Dictionary mapping parameter names to lists of
            values to test.

    Returns:
        SensitivityResult containing baseline and variations.

    Example:
        >>> def score(lat, lon, radius):
        ...     return lat + lon + radius
        >>> result = analyze_sensitivity(
        ...     score,
        ...     {"lat": 41.0, "lon": 29.0, "radius": 1.0},
        ...     {"radius": [0.5, 1.0, 1.5, 2.0]},
        ... )
        >>> print(result.variations["radius"])
    """
    baseline = func(**base_params)
    results: dict[str, list[Any]] = {}

    for param, values in param_ranges.items():
        param_results: list[Any] = []
        for val in values:
            test_params = base_params.copy()
            test_params[param] = val
            param_results.append(func(**test_params))
        results[param] = param_results

    return SensitivityResult(
        baseline=baseline,
        variations=results,
        parameters=param_ranges,
    )
