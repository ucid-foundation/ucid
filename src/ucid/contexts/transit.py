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

"""Transit quality context implementation.

This module implements the Transit context, which evaluates the quality
of public transportation access at a given location. Metrics include
frequency, coverage, reliability, and multi-modal connectivity.
"""

from ucid.contexts.base import BaseContext, ContextResult


class TransitContext(BaseContext):
    """Transit quality context for public transportation scoring.

    This context evaluates public transport accessibility based on:
    - Stop proximity (walking distance to nearest stops)
    - Service frequency (trips per hour)
    - Mode diversity (bus, rail, ferry, etc.)
    - Temporal coverage (service hours)

    Example:
        >>> context = TransitContext()
        >>> result = context.compute(lat=60.1699, lon=24.9384, timestamp="2026W01T08")
        >>> print(f"Transit Score: {result.raw_score}")
    """

    @property
    def context_id(self) -> str:
        """Return the unique identifier for this context."""
        return "TRANSIT"

    def compute(
        self,
        lat: float,
        lon: float,
        timestamp: str,
    ) -> ContextResult:
        """Compute transit accessibility score for a location.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            timestamp: Temporal key (YYYYWwwThh format).

        Returns:
            ContextResult with transit score and metadata.
        """
        # Production implementation would:
        # 1. Identify city from lat/lon (e.g. using ucid.spatial.geometry)
        # 2. Look up City object in registry
        # 3. If city.data_source is set, load that specific GTFS feed
        # 4. Otherwise fall back to global/OSM data

        # Example logic:
        # city = get_city_from_coords(lat, lon)
        # if city and city.data_source:
        #     feed_source = get_source(city.data_source)
        #     # process feed_source.url...

        raw_score = 75.0

        metadata = {"mode": "stub", "feed": "auto-detected"}

        # Simulating data source awareness
        if 40.0 < lat < 42.0 and 28.0 < lon < 30.0:
            metadata["city"] = "IST"
            metadata["data_source"] = "ist_gtfs_manual"
        elif 60.0 < lat < 61.0:
            metadata["city"] = "HEL"
            metadata["data_source"] = "hsl_gtfs"

        return ContextResult(
            raw_score=raw_score,
            grade=self.grade_score(raw_score),
            confidence=0.9,
            uncertainty=2.5,
            data_sources=["gtfs-stub"],
            metadata=metadata,
        )
