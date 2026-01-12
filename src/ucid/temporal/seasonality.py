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

"""Seasonal decomposition for time series analysis.

This module provides functions for decomposing time series data
into trend, seasonal, and residual components.
"""

from dataclasses import dataclass

import numpy as np


@dataclass
class SeasonalDecomposition:
    """Result of seasonal decomposition.

    Attributes:
        trend: Trend component of the time series.
        seasonal: Seasonal component.
        residual: Residual (remainder) component.
    """

    trend: list[float]
    seasonal: list[float]
    residual: list[float]


def decompose_seasonality(
    values: list[float],
    period: int,
) -> SeasonalDecomposition:
    """Decompose time series into trend, seasonal, and residual components.

    Uses an additive decomposition model: Y = T + S + R

    Args:
        values: Time series values.
        period: Seasonal period (e.g., 12 for monthly data with yearly cycle).

    Returns:
        SeasonalDecomposition with trend, seasonal, and residual components.

    Note:
        This is a simplified implementation. Production should use
        statsmodels.tsa.seasonal.seasonal_decompose.

    Example:
        >>> result = decompose_seasonality([70, 75, 80, 85, 70, 75], period=4)
        >>> print(result.trend)
    """
    n = len(values)
    if n < period:
        return SeasonalDecomposition(
            trend=list(values),
            seasonal=[0.0] * n,
            residual=[0.0] * n,
        )

    # Simple moving average for trend
    arr = np.array(values, dtype=float)
    trend = np.convolve(arr, np.ones(period) / period, mode="same")

    # Seasonal component (simplified)
    seasonal = arr - trend

    # Residual
    residual = arr - trend - seasonal

    return SeasonalDecomposition(
        trend=[float(x) for x in trend],
        seasonal=[float(x) for x in seasonal],
        residual=[float(x) for x in residual],
    )
