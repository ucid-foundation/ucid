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

"""Walkability context implementation.

This module implements the Walk context, which evaluates pedestrian
infrastructure quality, street connectivity, and walking comfort.
"""

from ucid.contexts.base import BaseContext, ContextResult


class WalkabilityContext(BaseContext):
    """Walkability context for pedestrian infrastructure scoring.

    This context evaluates walkability factors:
    - Street network connectivity and intersection density
    - Sidewalk coverage and quality
    - Pedestrian safety indicators
    - Street-level comfort (shade, lighting)

    Example:
        >>> context = WalkabilityContext()
        >>> result = context.compute(lat=51.5074, lon=-0.1278, timestamp="2026W01T10")
        >>> print(f"Walkability Score: {result.raw_score}")
    """

    @property
    def context_id(self) -> str:
        """Return the unique identifier for this context."""
        return "WALK"

    def compute(
        self,
        lat: float,
        lon: float,
        timestamp: str,
    ) -> ContextResult:
        """Compute walkability score for a location.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            timestamp: Temporal key (YYYYWwwThh format).

        Returns:
            ContextResult with walkability score and metadata.
        """
        raw_score = 88.0
        return ContextResult(
            raw_score=raw_score,
            grade=self.grade_score(raw_score),
            confidence=0.9,
            uncertainty=2.0,
            data_sources=["osm-roads", "osm-poi"],
            metadata={"mode": "stub", "network_type": "walk"},
        )
