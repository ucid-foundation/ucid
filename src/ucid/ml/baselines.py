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

"""Baseline models for UCID score prediction.

This module provides simple baseline models that serve as reference points
for evaluating more complex prediction models.
"""

from typing import Any


class MeanRegressor:
    """Simple baseline regressor that predicts the mean of training targets.

    This model provides a trivial baseline for regression tasks. It predicts
    the mean of the training target values for all inputs, which is useful
    for establishing a minimum performance threshold.

    Attributes:
        mean: The computed mean of training targets.

    Example:
        >>> regressor = MeanRegressor()
        >>> regressor.fit(X_train, [70.0, 80.0, 90.0])
        >>> predictions = regressor.predict(X_test)
    """

    def __init__(self) -> None:
        """Initialize the MeanRegressor with default mean of 0.0."""
        self.mean: float = 0.0

    def fit(self, features: Any, targets: list[float]) -> None:
        """Fit the model by computing the mean of target values.

        Args:
            features: Feature matrix (ignored, included for API compatibility).
            targets: List of target values to compute the mean from.

        Raises:
            ZeroDivisionError: If targets is empty.
        """
        if not targets:
            raise ZeroDivisionError("Cannot compute mean of empty targets list")
        self.mean = sum(targets) / len(targets)

    def predict(self, features: Any) -> list[float]:
        """Predict by returning the mean for each sample.

        Args:
            features: Feature matrix to predict for.

        Returns:
            List of predictions, all equal to the training mean.
        """
        return [self.mean] * len(features)
