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

"""Feature engineering pipeline for UCID prediction models.

This module provides a production-grade feature engineering pipeline that
transforms UCID context data into model-ready feature matrices using
scikit-learn transformers.
"""

from typing import Any

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin  # type: ignore[import-untyped]
from sklearn.compose import ColumnTransformer  # type: ignore[import-untyped]
from sklearn.preprocessing import (  # type: ignore[import-untyped]
    OneHotEncoder,
    StandardScaler,
)


class FeaturePipeline(BaseEstimator, TransformerMixin):
    """Production-grade feature engineering pipeline.

    Wraps scikit-learn pipelines to transform UCID context data into
    model-ready feature arrays. Automatically detects numerical and
    categorical columns if not specified.

    Attributes:
        numerical_cols: List of numerical column names to scale.
        categorical_cols: List of categorical column names to encode.
        pipeline: The fitted ColumnTransformer instance.
        is_fitted: Whether the pipeline has been fitted.

    Example:
        >>> pipeline = FeaturePipeline()
        >>> data = [{"score": 85.0, "grade": "A"}, {"score": 70.0, "grade": "B"}]
        >>> pipeline.fit(data)
        >>> features = pipeline.transform(data)
    """

    def __init__(
        self,
        numerical_cols: list[str] | None = None,
        categorical_cols: list[str] | None = None,
    ) -> None:
        """Initialize the FeaturePipeline.

        Args:
            numerical_cols: List of numerical column names. If None, will be
                auto-detected during fit.
            categorical_cols: List of categorical column names. If None, will
                be auto-detected during fit.
        """
        self.numerical_cols: list[str] = numerical_cols or []
        self.categorical_cols: list[str] = categorical_cols or []
        self.pipeline: ColumnTransformer | None = None
        self.is_fitted: bool = False

    def fit(
        self,
        data: list[dict[str, Any]] | pd.DataFrame,
        y: Any = None,
    ) -> "FeaturePipeline":
        """Fit the preprocessors on training data.

        Args:
            data: Training data as list of dicts or DataFrame.
            y: Ignored. Included for scikit-learn API compatibility.

        Returns:
            The fitted FeaturePipeline instance.
        """
        del y  # Unused, included for API compatibility
        df = self._ensure_dataframe(data)

        # Auto-detect columns if not provided
        if not self.numerical_cols and not self.categorical_cols:
            self.numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            self.categorical_cols = df.select_dtypes(include=["object", "category"]).columns.tolist()

        transformers: list[tuple[str, Any, list[str]]] = []
        if self.numerical_cols:
            transformers.append(("num", StandardScaler(), self.numerical_cols))

        if self.categorical_cols:
            transformers.append(
                (
                    "cat",
                    OneHotEncoder(handle_unknown="ignore"),
                    self.categorical_cols,
                )
            )

        self.pipeline = ColumnTransformer(transformers=transformers)
        self.pipeline.fit(df)
        self.is_fitted = True
        return self

    def transform(
        self,
        data: list[dict[str, Any]] | pd.DataFrame,
    ) -> np.ndarray:
        """Transform data into feature matrix.

        Args:
            data: Data to transform as list of dicts or DataFrame.

        Returns:
            NumPy array of transformed features.

        Raises:
            RuntimeError: If pipeline has not been fitted.
        """
        if not self.is_fitted or self.pipeline is None:
            raise RuntimeError("Pipeline must be fitted before transform.")

        df = self._ensure_dataframe(data)
        return self.pipeline.transform(df)

    def _ensure_dataframe(
        self,
        data: list[dict[str, Any]] | pd.DataFrame,
    ) -> pd.DataFrame:
        """Convert input data to DataFrame if needed.

        Args:
            data: Input data as list of dicts or DataFrame.

        Returns:
            Data as a pandas DataFrame.
        """
        if isinstance(data, pd.DataFrame):
            return data
        return pd.DataFrame(data)
