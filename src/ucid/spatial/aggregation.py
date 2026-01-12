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

"""Spatial aggregation functions for UCID analysis.

This module provides functions for aggregating scores and values
across spatial regions.
"""

from enum import Enum

import numpy as np


class AggregationMethod(str, Enum):
    """Supported aggregation methods."""

    MEAN = "mean"
    MEDIAN = "median"
    MAX = "max"
    MIN = "min"
    SUM = "sum"


def aggregate_scores(
    scores: list[float],
    method: str | AggregationMethod = AggregationMethod.MEAN,
) -> float:
    """Aggregate a list of scores using the specified method.

    Args:
        scores: List of numeric scores to aggregate.
        method: Aggregation method. Options: mean, median, max, min, sum.
            Defaults to mean.

    Returns:
        Aggregated score value.

    Raises:
        ValueError: If method is not recognized.

    Example:
        >>> scores = [70.0, 80.0, 90.0]
        >>> aggregate_scores(scores, "mean")
        80.0
    """
    if not scores:
        return 0.0

    method_str = method.value if isinstance(method, AggregationMethod) else method

    if method_str == "mean":
        return float(np.mean(scores))
    if method_str == "median":
        return float(np.median(scores))
    if method_str == "max":
        return float(np.max(scores))
    if method_str == "min":
        return float(np.min(scores))
    if method_str == "sum":
        return float(np.sum(scores))

    raise ValueError(f"Unknown aggregation method: {method}")


def weighted_average_spatial(
    values: list[float],
    weights: list[float],
) -> float:
    """Compute weighted average of spatial values.

    Args:
        values: List of values to average.
        weights: List of weights (must match length of values).

    Returns:
        Weighted average.

    Example:
        >>> weighted_average_spatial([80.0, 90.0], [1.0, 2.0])
        86.666...
    """
    if not values or not weights:
        return 0.0
    return float(np.average(values, weights=weights))
