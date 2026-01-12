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

"""Anomaly detection algorithms for time series data.

This module provides functions for detecting outliers and anomalies
in time series data using statistical methods.
"""

import numpy as np


def detect_anomalies_zscore(
    values: list[float],
    threshold: float = 3.0,
) -> list[bool]:
    """Detect anomalies using Z-score method.

    Values with Z-scores exceeding the threshold are marked as anomalies.

    Args:
        values: List of numeric values.
        threshold: Number of standard deviations for anomaly detection.
            Defaults to 3.0.

    Returns:
        Boolean list where True indicates an anomaly.

    Example:
        >>> is_anomaly = detect_anomalies_zscore([10, 12, 11, 50, 10])
        >>> print(is_anomaly)  # [False, False, False, True, False]
    """
    if not values:
        return []

    arr = np.array(values)
    mean = np.mean(arr)
    std = np.std(arr)

    if std == 0:
        return [False] * len(values)

    z_scores = (arr - mean) / std
    return [bool(abs(z) > threshold) for z in z_scores]


def detect_anomalies_iqr(values: list[float]) -> list[bool]:
    """Detect anomalies using Interquartile Range (IQR) method.

    Values outside 1.5 * IQR from the first and third quartiles
    are marked as anomalies.

    Args:
        values: List of numeric values.

    Returns:
        Boolean list where True indicates an anomaly.

    Example:
        >>> is_anomaly = detect_anomalies_iqr([10, 12, 11, 50, 10])
    """
    if not values:
        return []

    arr = np.array(values)
    q75 = np.percentile(arr, 75)
    q25 = np.percentile(arr, 25)
    iqr = q75 - q25

    lower_bound = q25 - (1.5 * iqr)
    upper_bound = q75 + (1.5 * iqr)

    return [bool(v < lower_bound or v > upper_bound) for v in values]


def get_anomaly_indices(anomaly_mask: list[bool]) -> list[int]:
    """Get indices of anomalies from a boolean mask.

    Args:
        anomaly_mask: Boolean list from detect_anomalies_* functions.

    Returns:
        List of indices where anomalies occur.
    """
    return [i for i, is_anomaly in enumerate(anomaly_mask) if is_anomaly]
