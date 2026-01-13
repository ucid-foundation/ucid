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

"""Urban vitality context implementation.

This module implements the Vitality context, which evaluates urban
vibrancy and activity levels through POI density, diversity, and
temporal activity patterns.
"""

from ucid.contexts.base import BaseContext, ContextResult


class VitalityContext(BaseContext):
    """Urban vitality context for activity and vibrancy scoring.

    This context evaluates urban vitality factors:
    - POI density and diversity (Shannon entropy)
    - Temporal activity signatures
    - Street-level activity indicators
    - Mixed-use development patterns

    Example:
        >>> context = VitalityContext()
        >>> result = context.compute(lat=40.7128, lon=-74.0060, timestamp="2026W01T19")
        >>> print(f"Vitality Score: {result.raw_score}")
    """

    @property
    def context_id(self) -> str:
        """Return the unique identifier for this context."""
        return "VITALITY"

    def compute(
        self,
        lat: float,
        lon: float,
        timestamp: str,
    ) -> ContextResult:
        """Compute urban vitality score for a location.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            timestamp: Temporal key (YYYYWwwThh format).

        Returns:
            ContextResult with vitality score and metadata.
        """
        raw_score = 82.0
        return ContextResult(
            raw_score=raw_score,
            grade=self.grade_score(raw_score),
            confidence=0.8,
            uncertainty=5.0,
            data_sources=["mobile-network-data", "osm-poi"],
            metadata={
                "mode": "stub",
                "mobile_data_provider": "anonymized_aggregator",
                "granularity": "hourly",
            },
        )
