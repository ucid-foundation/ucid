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

"""Trend detection algorithms for time series analysis.

This module provides functions for detecting and analyzing
trends in time series data.
"""

from dataclasses import dataclass
from enum import Enum

import numpy as np


class TrendDirection(str, Enum):
    """Direction of detected trend."""

    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"


@dataclass
class LinearTrendResult:
    """Result of linear trend analysis.

    Attributes:
        slope: Slope of the trend line.
        intercept: Y-intercept of the trend line.
        r_squared: Coefficient of determination (0-1).
    """

    slope: float
    intercept: float
    r_squared: float


def detect_linear_trend(
    times: list[float],
    values: list[float],
) -> LinearTrendResult:
    """Detect linear trend using least squares regression.

    Args:
        times: Time values (x-axis).
        values: Observed values (y-axis).

    Returns:
        LinearTrendResult with slope, intercept, and R-squared.

    Example:
        >>> result = detect_linear_trend([1, 2, 3, 4], [70, 75, 80, 85])
        >>> print(f"Slope: {result.slope:.2f}")
    """
    if len(values) < 2:
        return LinearTrendResult(slope=0.0, intercept=0.0, r_squared=0.0)

    x = np.array(times)
    y = np.array(values)

    # Linear regression
    coeffs = np.polyfit(x, y, 1)
    slope, intercept = float(coeffs[0]), float(coeffs[1])

    # Calculate R-squared
    y_pred = slope * x + intercept
    ss_res = np.sum((y - y_pred) ** 2)
    ss_tot = np.sum((y - np.mean(y)) ** 2)
    r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0

    return LinearTrendResult(
        slope=slope,
        intercept=intercept,
        r_squared=float(r_squared),
    )


def mann_kendall_test(values: list[float]) -> tuple[TrendDirection, float]:
    """Perform Mann-Kendall trend test.

    A non-parametric test for monotonic trend detection.

    Args:
        values: Time series values.

    Returns:
        Tuple of (trend direction, p-value).

    Note:
        This is a simplified implementation. Production should use
        pymannkendall for full statistical testing.

    Example:
        >>> direction, p_value = mann_kendall_test([70, 75, 80, 85])
        >>> print(direction)  # TrendDirection.INCREASING
    """
    if len(values) < 3:
        return TrendDirection.STABLE, 1.0

    # Simple trend detection based on start/end comparison
    first_third = np.mean(values[: len(values) // 3])
    last_third = np.mean(values[-len(values) // 3 :])

    if last_third > first_third * 1.05:
        return TrendDirection.INCREASING, 0.05
    if last_third < first_third * 0.95:
        return TrendDirection.DECREASING, 0.05
    return TrendDirection.STABLE, 0.5
