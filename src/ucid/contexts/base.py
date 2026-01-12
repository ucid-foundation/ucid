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

"""Base classes for UCID context implementations.

This module defines the abstract base class and result dataclass that all
context implementations must use. Contexts compute scores for specific
urban quality dimensions (walkability, transit access, etc.).

Example:
    >>> from ucid.contexts.base import BaseContext, ContextResult
    >>> class MyContext(BaseContext):
    ...     @property
    ...     def context_id(self) -> str:
    ...         return "MYCTX"
    ...     def compute(self, lat, lon, timestamp) -> ContextResult:
    ...         return ContextResult(raw_score=75.0, grade="B", confidence=0.8)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ContextResult:
    """Result from a context scoring operation.

    This dataclass encapsulates all outputs from a context computation,
    including the score, grade, confidence, and any generated artifacts.

    Attributes:
        raw_score: Numeric score from 0 to 100.
        grade: Letter grade (A+, A, B, C, D, F).
        confidence: Confidence in the score (0.0 to 1.0).
        uncertainty: Measure of uncertainty (e.g., spatial radius in meters).
        data_sources: List of data sources used in computation.
        artifacts: Dictionary of artifact URLs or paths (e.g., isochrone GeoJSON).
        metadata: Additional metadata about the computation.
    """

    raw_score: float
    grade: str
    confidence: float
    uncertainty: float = 0.0
    data_sources: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseContext(ABC):
    """Abstract base class for all UCID contexts.

    Contexts are pluggable scoring algorithms that evaluate specific
    dimensions of urban quality. All contexts must implement the
    `compute` method and `context_id` property.

    Attributes:
        config: Optional configuration dictionary for the context.

    Example:
        >>> class TransitContext(BaseContext):
        ...     @property
        ...     def context_id(self) -> str:
        ...         return "TRANSIT"
        ...     def compute(self, lat, lon, timestamp) -> ContextResult:
        ...         # Implementation here
        ...         pass
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the context with optional configuration.

        Args:
            config: Optional dictionary of configuration parameters.
        """
        self.config = config or {}

    @property
    @abstractmethod
    def context_id(self) -> str:
        """Return the unique identifier for this context.

        Returns:
            Uppercase string identifier (e.g., "15MIN", "TRANSIT").
        """

    @abstractmethod
    def compute(
        self,
        lat: float,
        lon: float,
        timestamp: str,
    ) -> ContextResult:
        """Compute the context score for a location and time.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            timestamp: Temporal key (YYYYWwwThh format).

        Returns:
            ContextResult with score, grade, and metadata.

        Raises:
            UCIDContextError: If computation fails.
        """

    def grade_score(self, score: float) -> str:
        """Convert a raw score to a letter grade.

        Uses the standard UCID grading thresholds:
        - A+: 90-100
        - A: 80-89
        - B: 70-79
        - C: 60-69
        - D: 50-59
        - F: 0-49

        Args:
            score: Raw score from 0 to 100.

        Returns:
            Letter grade string.
        """
        if score >= 90:
            return "A+"
        if score >= 80:
            return "A"
        if score >= 70:
            return "B"
        if score >= 60:
            return "C"
        if score >= 50:
            return "D"
        return "F"
