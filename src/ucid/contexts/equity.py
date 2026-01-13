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

"""Equity analysis context implementation.

This module implements the Equity context, which evaluates access gaps
and socioeconomic disparities in urban services and opportunities.
"""

from ucid.contexts.base import BaseContext, ContextResult


class EquityContext(BaseContext):
    """Equity analysis context for access gap identification.

    This context evaluates equity-related urban factors:
    - Service access disparities
    - Gini coefficient for amenity distribution
    - Transportation equity metrics
    - Socioeconomic overlay analysis

    Example:
        >>> context = EquityContext()
        >>> result = context.compute(lat=41.015, lon=28.979, timestamp="2026W01T12")
        >>> print(f"Equity Score: {result.raw_score}")
    """

    @property
    def context_id(self) -> str:
        """Return the unique identifier for this context."""
        return "EQUITY"

    def compute(
        self,
        lat: float,
        lon: float,
        timestamp: str,
    ) -> ContextResult:
        """Compute equity score for a location.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            timestamp: Temporal key (YYYYWwwThh format).

        Returns:
            ContextResult with equity score and metadata.
        """
        raw_score = 70.0
        return ContextResult(
            raw_score=raw_score,
            grade=self.grade_score(raw_score),
            confidence=0.6,
            uncertainty=15.0,
            data_sources=["worldpop", "ghs-pop", "census-stub"],
            metadata={
                "mode": "stub",
                "population_grid": "WorldPop 100m",
                "reference_year": "2026",
            },
        )
