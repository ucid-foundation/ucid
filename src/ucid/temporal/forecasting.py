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

"""Forecasting wrappers for time series prediction.

This module provides wrapper functions for time series forecasting
using various methods including ARIMA and Prophet.
"""

from typing import Any


def forecast_arima(
    values: list[float],
    steps: int = 1,
) -> list[float]:
    """Forecast future values using ARIMA model.

    Args:
        values: Historical time series values.
        steps: Number of future periods to forecast. Defaults to 1.

    Returns:
        List of forecasted values.

    Note:
        This is a stub implementation. Production should use
        statsmodels.tsa.arima.model.ARIMA.

    Example:
        >>> forecast = forecast_arima([100, 105, 110], steps=3)
    """
    if not values:
        return [0.0] * steps
    # Simple naive forecast - last value carried forward
    return [values[-1]] * steps


def forecast_prophet(
    dates: list[str],
    values: list[float],
    steps: int = 1,
) -> dict[str, Any]:
    """Forecast using Facebook Prophet model.

    Args:
        dates: List of date strings in ISO format.
        values: Historical values corresponding to each date.
        steps: Number of future periods to forecast. Defaults to 1.

    Returns:
        Dictionary with 'forecast' key containing predicted values.

    Note:
        This is a stub implementation. Production should use
        the prophet library.

    Example:
        >>> result = forecast_prophet(
        ...     ["2026-01-01", "2026-01-08"],
        ...     [100, 105],
        ...     steps=4
        ... )
    """
    del dates  # Reserved for production use
    if not values:
        return {"forecast": [0.0] * steps}
    return {"forecast": [values[-1]] * steps}


def forecast_exponential_smoothing(
    values: list[float],
    steps: int = 1,
    alpha: float = 0.3,
) -> list[float]:
    """Forecast using simple exponential smoothing.

    Args:
        values: Historical time series values.
        steps: Number of future periods to forecast. Defaults to 1.
        alpha: Smoothing factor (0 < alpha < 1). Defaults to 0.3.

    Returns:
        List of forecasted values.

    Example:
        >>> forecast = forecast_exponential_smoothing([100, 105, 110], steps=3)
    """
    if not values:
        return [0.0] * steps

    # Calculate exponentially smoothed value
    smoothed = values[0]
    for v in values[1:]:
        smoothed = alpha * v + (1 - alpha) * smoothed

    return [smoothed] * steps
