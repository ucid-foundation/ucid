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

"""Machine learning predictors for UCID.

This module provides ML models for predicting urban context scores.
"""

from abc import ABC, abstractmethod
from typing import Any


class BasePredictor(ABC):
    """Abstract base class for ML predictors.

    All UCID predictors must inherit from this class and implement
    the fit and predict methods.
    """

    @abstractmethod
    def fit(self, X: Any, y: Any) -> None:
        """Fit the model to training data.

        Args:
            X: Feature matrix.
            y: Target values.
        """
        pass

    @abstractmethod
    def predict(self, X: Any) -> Any:
        """Generate predictions.

        Args:
            X: Feature matrix.

        Returns:
            Predicted values.
        """
        pass


class UCIDPredictor(BasePredictor):
    """Predictor for UCID context scores.

    This class provides a unified interface for predicting context
    scores using various ML algorithms.

    Attributes:
        context: Context identifier this predictor is trained for.
        model: Underlying ML model (sklearn-compatible).

    Example:
        >>> predictor = UCIDPredictor(context="15MIN")
        >>> predictor.fit(X_train, y_train)
        >>> predictions = predictor.predict(X_test)
    """

    def __init__(self, context: str, model: Any | None = None) -> None:
        """Initialize the predictor.

        Args:
            context: Context identifier (e.g., "15MIN").
            model: Optional sklearn-compatible model.
        """
        self.context = context
        self.model = model

    def fit(self, X: Any, y: Any) -> None:
        """Fit the model to training data.

        Args:
            X: Feature matrix.
            y: Target values.
        """
        if self.model is not None:
            self.model.fit(X, y)

    def predict(self, X: Any) -> list[float]:
        """Generate predictions.

        Args:
            X: Feature matrix.

        Returns:
            List of predicted values.
        """
        if self.model is not None:
            return list(self.model.predict(X))
        return [0.0] * len(X)

    def predict_with_uncertainty(self, X: Any) -> tuple[list[float], list[float]]:
        """Generate predictions with uncertainty estimates.

        Args:
            X: Feature matrix.

        Returns:
            Tuple of (predictions, uncertainties).
        """
        predictions = self.predict(X)
        uncertainties = [0.1] * len(predictions)  # Stub
        return predictions, uncertainties
