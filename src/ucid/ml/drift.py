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

"""Distribution drift detection for UCID models.

This module provides functions to detect distribution drift between
reference and current data, helping identify when models may need
retraining due to changes in underlying data patterns.
"""

from typing import Any


def detect_drift(
    reference: list[float],
    current: list[float],
) -> dict[str, Any]:
    """Detect distribution drift between reference and current samples.

    Uses the Kolmogorov-Smirnov two-sample test to determine if the
    current distribution significantly differs from the reference.

    Args:
        reference: Sample from the reference distribution (e.g., training data).
        current: Sample from the current distribution (e.g., production data).

    Returns:
        Dictionary containing:
            - drift_detected: Boolean indicating if drift was detected (p < 0.05)
            - p_value: P-value from the KS test (if scipy available)
            - error: Error message (if scipy not installed)

    Example:
        >>> ref_data = [1.0, 2.0, 3.0, 4.0, 5.0]
        >>> new_data = [1.5, 2.5, 3.5, 4.5, 5.5]
        >>> result = detect_drift(ref_data, new_data)
        >>> if result["drift_detected"]:
        ...     print("Data drift detected, consider retraining")
    """
    try:
        from scipy import stats  # type: ignore[import-untyped]

        ks_stat, p_value = stats.ks_2samp(reference, current)
        return {
            "drift_detected": p_value < 0.05,
            "p_value": float(p_value),
            "ks_statistic": float(ks_stat),
        }
    except ImportError:
        return {
            "drift_detected": False,
            "error": "scipy not installed - run: pip install scipy",
        }
