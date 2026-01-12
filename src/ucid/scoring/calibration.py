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

"""Model calibration utilities for UCID scoring.

This module provides functions for evaluating and improving the
calibration of probabilistic predictions.
"""

import numpy as np


def compute_calibration_curve(
    y_true: list[int],
    y_prob: list[float],
    n_bins: int = 10,
) -> tuple[np.ndarray, np.ndarray]:
    """Compute calibration curve (reliability diagram).

    Calculates the relationship between predicted probabilities and
    actual outcomes, useful for identifying over/under-confident models.

    Args:
        y_true: True binary labels (0 or 1).
        y_prob: Predicted probabilities for the positive class.
        n_bins: Number of bins for grouping predictions. Defaults to 10.

    Returns:
        Tuple of (fraction_of_positives, mean_predicted_value) arrays.

    Raises:
        ImportError: If scikit-learn is not installed.

    Example:
        >>> frac_pos, mean_pred = compute_calibration_curve([0, 1, 1], [0.1, 0.8, 0.9])
    """
    from sklearn.calibration import calibration_curve  # type: ignore[import-untyped]

    return calibration_curve(y_true, y_prob, n_bins=n_bins)


def brier_score(y_true: list[int], y_prob: list[float]) -> float:
    """Compute Brier score for probabilistic predictions.

    The Brier score measures the mean squared difference between
    predicted probabilities and actual outcomes. Lower is better.

    Args:
        y_true: True binary labels (0 or 1).
        y_prob: Predicted probabilities for the positive class.

    Returns:
        Brier score (0.0 = perfect, 1.0 = worst).

    Raises:
        ImportError: If scikit-learn is not installed.

    Example:
        >>> score = brier_score([0, 1, 1], [0.1, 0.8, 0.9])
        >>> print(f"Brier score: {score:.4f}")
    """
    from sklearn.metrics import brier_score_loss  # type: ignore[import-untyped]

    return brier_score_loss(y_true, y_prob)


def expected_calibration_error(
    y_true: list[int],
    y_prob: list[float],
    n_bins: int = 10,
) -> float:
    """Compute Expected Calibration Error (ECE).

    ECE is a weighted average of the absolute difference between
    predicted probabilities and actual accuracy within each bin.

    Args:
        y_true: True binary labels.
        y_prob: Predicted probabilities.
        n_bins: Number of bins. Defaults to 10.

    Returns:
        Expected calibration error (0.0 = perfectly calibrated).
    """
    y_true_arr = np.array(y_true)
    y_prob_arr = np.array(y_prob)

    bin_edges = np.linspace(0, 1, n_bins + 1)
    ece = 0.0

    for i in range(n_bins):
        mask = (y_prob_arr >= bin_edges[i]) & (y_prob_arr < bin_edges[i + 1])
        if mask.sum() > 0:
            bin_acc = y_true_arr[mask].mean()
            bin_conf = y_prob_arr[mask].mean()
            bin_weight = mask.sum() / len(y_true)
            ece += bin_weight * abs(bin_acc - bin_conf)

    return float(ece)
