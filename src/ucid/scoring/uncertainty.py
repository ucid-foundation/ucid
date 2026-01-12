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

"""Uncertainty quantification methods for UCID scoring.

This module provides functions for quantifying and reporting
uncertainty in UCID scores and predictions.
"""

from dataclasses import dataclass

import numpy as np


@dataclass
class ConfidenceInterval:
    """A confidence interval.

    Attributes:
        lower: Lower bound of the interval.
        upper: Upper bound of the interval.
        confidence: Confidence level (e.g., 0.95 for 95%).
    """

    lower: float
    upper: float
    confidence: float


def calculate_uncertainty_interval(
    values: list[float],
    confidence: float = 0.95,
) -> ConfidenceInterval:
    """Calculate a confidence interval for a list of values.

    Uses percentile-based intervals, suitable for non-parametric
    distributions.

    Args:
        values: List of numeric values (e.g., bootstrap samples).
        confidence: Confidence level (0.0 to 1.0). Defaults to 0.95.

    Returns:
        ConfidenceInterval with lower and upper bounds.

    Example:
        >>> samples = [85.0, 86.0, 84.0, 87.0, 85.5]
        >>> ci = calculate_uncertainty_interval(samples, confidence=0.90)
        >>> print(f"90% CI: [{ci.lower:.1f}, {ci.upper:.1f}]")
    """
    if not values:
        return ConfidenceInterval(lower=0.0, upper=0.0, confidence=confidence)

    alpha = 1.0 - confidence
    lower_percentile = alpha / 2.0 * 100
    upper_percentile = (1.0 - alpha / 2.0) * 100

    return ConfidenceInterval(
        lower=float(np.percentile(values, lower_percentile)),
        upper=float(np.percentile(values, upper_percentile)),
        confidence=confidence,
    )


# H3 resolution to approximate edge length in meters
_H3_EDGE_LENGTHS: dict[int, float] = {
    7: 1220.0,
    8: 461.0,
    9: 174.0,
    10: 65.9,
    11: 24.9,
    12: 9.4,
    13: 3.5,
}


def estimate_spatial_uncertainty(
    lat: float,
    lon: float,
    resolution: int,
) -> float:
    """Estimate spatial uncertainty in meters based on H3 resolution.

    The uncertainty corresponds to the approximate edge length of
    an H3 hexagon at the given resolution.

    Args:
        lat: Latitude (unused, included for future improvements).
        lon: Longitude (unused, included for future improvements).
        resolution: H3 resolution level (7-13).

    Returns:
        Estimated uncertainty in meters.

    Example:
        >>> uncertainty = estimate_spatial_uncertainty(41.015, 28.979, 9)
        >>> print(f"Spatial uncertainty: ±{uncertainty:.0f}m")
    """
    del lat, lon  # Unused, but reserved for latitude-dependent calculations
    return _H3_EDGE_LENGTHS.get(resolution, 100.0)
