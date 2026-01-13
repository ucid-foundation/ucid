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

"""Score normalization utilities for UCID.

This module provides functions for normalizing raw scores to the
standard 0-100 scale used across all UCID contexts.
"""


def normalize_score(
    value: float,
    min_val: float,
    max_val: float,
    invert: bool = False,
) -> float:
    """Normalize a value to the 0-100 scale.

    Args:
        value: Raw value to normalize.
        min_val: Minimum value in the range.
        max_val: Maximum value in the range.
        invert: If True, higher values map to lower scores.

    Returns:
        Normalized score in [0, 100].
    """
    if max_val == min_val:
        return 50.0

    normalized = (value - min_val) / (max_val - min_val) * 100
    normalized = max(0.0, min(100.0, normalized))

    if invert:
        normalized = 100.0 - normalized

    return normalized


def min_max_normalize(values: list[float]) -> list[float]:
    """Min-max normalize a list of values to 0-100.

    Args:
        values: List of values to normalize.

    Returns:
        List of normalized values.
    """
    if not values:
        return []

    min_val = min(values)
    max_val = max(values)

    return [normalize_score(v, min_val, max_val) for v in values]


def z_score_normalize(
    values: list[float],
    mean: float | None = None,
    std: float | None = None,
) -> list[float]:
    """Z-score normalize values and convert to 0-100 scale.

    Args:
        values: List of values to normalize.
        mean: Optional pre-computed mean.
        std: Optional pre-computed standard deviation.

    Returns:
        List of normalized values.
    """
    if not values:
        return []

    if mean is None:
        mean = sum(values) / len(values)

    if std is None:
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = variance**0.5

    if std == 0:
        return [50.0] * len(values)

    z_scores = [(v - mean) / std for v in values]
    # Convert z-scores to 0-100 (assume z in [-3, 3] maps to [0, 100])
    return [max(0.0, min(100.0, (z + 3) / 6 * 100)) for z in z_scores]
