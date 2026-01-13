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

"""Evaluation metrics for UCID prediction models.

This module provides functions for evaluating the performance of UCID
prediction models, including regression metrics and cross-validation.
"""

import math
from typing import Any


def calculate_metrics(y_true: list[float], y_pred: list[float]) -> dict[str, float]:
    """Calculate regression evaluation metrics.

    Computes common regression metrics including Mean Squared Error (MSE),
    Mean Absolute Error (MAE), and Root Mean Squared Error (RMSE).

    Args:
        y_true: Ground truth target values.
        y_pred: Predicted values from the model.

    Returns:
        Dictionary containing the following metrics:
            - mse: Mean Squared Error
            - mae: Mean Absolute Error
            - rmse: Root Mean Squared Error

    Raises:
        ZeroDivisionError: If input lists are empty.
        ValueError: If input lists have different lengths.

    Example:
        >>> metrics = calculate_metrics([1.0, 2.0, 3.0], [1.1, 2.2, 2.9])
        >>> print(f"RMSE: {metrics['rmse']:.3f}")
    """
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length")
    if not y_true:
        raise ZeroDivisionError("Cannot calculate metrics for empty lists")

    mse = sum((t - p) ** 2 for t, p in zip(y_true, y_pred, strict=True)) / len(y_true)
    mae = sum(abs(t - p) for t, p in zip(y_true, y_pred, strict=True)) / len(y_true)
    rmse = math.sqrt(mse)

    return {
        "mse": mse,
        "mae": mae,
        "rmse": rmse,
    }


def cross_validate(
    model: Any,
    features: Any,
    targets: Any,
    k: int = 5,
) -> dict[str, float]:
    """Perform k-fold cross-validation on a model.

    This is a stub implementation that returns placeholder results.
    Full implementation would split data into k folds and evaluate.

    Args:
        model: The model to evaluate (must have fit and predict methods).
        features: Feature matrix for training and validation.
        targets: Target values for training and validation.
        k: Number of folds for cross-validation. Defaults to 5.

    Returns:
        Dictionary containing cross-validation metrics:
            - mean_rmse: Mean RMSE across all folds

    Note:
        This is currently a stub implementation.
    """
    del model, features, targets, k  # Unused in stub
    return {"mean_rmse": 0.0}
