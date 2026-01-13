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

"""Climate resilience context implementation.

This module implements the Climate context, which evaluates climate
resilience factors including heat island effect, flood risk, and
green infrastructure coverage.
"""

from ucid.contexts.base import BaseContext, ContextResult


class ClimateContext(BaseContext):
    """Climate resilience context for environmental quality scoring.

    This context evaluates climate-related urban quality factors:
    - Urban heat island intensity
    - Green space accessibility and coverage
    - Flood risk exposure
    - Air quality indicators

    Example:
        >>> context = ClimateContext()
        >>> result = context.compute(lat=41.015, lon=28.979, timestamp="2026W28T14")
        >>> print(f"Climate Score: {result.raw_score}")
    """

    @property
    def context_id(self) -> str:
        """Return the unique identifier for this context."""
        return "CLIMATE"

    def compute(
        self,
        lat: float,
        lon: float,
        timestamp: str,
    ) -> ContextResult:
        """Compute climate resilience score for a location.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            timestamp: Temporal key (YYYYWwwThh format).

        Returns:
            ContextResult with climate score and metadata.
        """
        raw_score = 65.0
        return ContextResult(
            raw_score=raw_score,
            grade=self.grade_score(raw_score),
            confidence=0.7,
            uncertainty=10.0,
            data_sources=["sentinel-2", "osm-greenspace"],
            metadata={
                "mode": "stub",
                "sentinel_layers": ["NDVI", "LST"],
                "resolution": "10m",
            },
        )
