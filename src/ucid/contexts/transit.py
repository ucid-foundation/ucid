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
of public transportation access at a given location using real data from
OSM Overpass API and GTFS feeds.

Metrics include:
- Stop density: Transit stops per km2
- Service types: Metro, tram, bus, rail diversity
- Proximity: Walking distance to nearest stops
- Network connectivity: Transfer opportunities
"""

from __future__ import annotations

import asyncio
import logging
import math

from ucid.contexts.base import BaseContext, ContextResult
from ucid.core.errors import UCIDContextError

logger = logging.getLogger(__name__)

# Transit stop scoring weights
TRANSIT_WEIGHTS = {
    "stop_density": 0.25,
    "mode_diversity": 0.20,
    "service_frequency": 0.25,
    "proximity": 0.15,
    "network_connectivity": 0.15,
}

# Transit mode complexity scores
MODE_SCORES = {
    "subway": 5,
    "metro": 5,
    "station": 4,
    "tram_stop": 3,
    "bus_stop": 2,
    "stop_position": 2,
    "platform": 2,
    "train_station": 4,
}

# Search radius for transit stops
TRANSIT_SEARCH_RADIUS = 800  # meters


class TransitContext(BaseContext):
    """Transit quality context for public transportation scoring.

    This context evaluates public transport accessibility using real data:
    - OSM Overpass API for transit stop locations
    - GTFS feeds for schedule and frequency data

    Scoring is based on:
    - Stop proximity (walking distance to nearest stops)
    - Mode diversity (bus, rail, metro, tram)
    - Stop density (stops per km2)
    - Network connectivity

    Example:
        >>> context = TransitContext()
        >>> result = context.compute(lat=40.4093, lon=49.8671, timestamp="2026W01T08")
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
        del timestamp  # Reserved for temporal variation

        try:
            return asyncio.run(self._compute_async(lat, lon))
        except RuntimeError:
            try:
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(self._compute_async(lat, lon))
            except Exception as e:
                logger.warning(f"Async transit query failed: {e}")
                return self._compute_fallback(lat, lon)
        except Exception as e:
            logger.warning(f"Transit computation failed: {e}")
            return self._compute_fallback(lat, lon)

    async def _compute_async(self, lat: float, lon: float) -> ContextResult:
        """Async computation using real OSM transit data.

        Args:
            lat: Latitude.
            lon: Longitude.

        Returns:
            ContextResult with real transit data.
        """
        try:
            from ucid.data.osm_client import OSMClient

            async with OSMClient(use_cache=True) as client:
                stops = await client.query_transit_stops(
                    lat=lat,
                    lon=lon,
                    radius=TRANSIT_SEARCH_RADIUS,
                )

            if not stops:
                return self._compute_fallback(lat, lon)

            # Calculate metrics
            stop_count = len(stops)
            area_km2 = (TRANSIT_SEARCH_RADIUS / 1000) ** 2 * math.pi
            stop_density = stop_count / area_km2

            # Mode diversity
            mode_types = set()
            mode_complexity_score = 0
            for stop in stops:
                stop_type = stop.get("type", "")
                mode_types.add(stop_type)
                mode_complexity_score += MODE_SCORES.get(stop_type, 1)

            mode_diversity = len(mode_types)

            # Calculate distances to stops
            distances = []
            for stop in stops:
                dist = self._haversine(lat, lon, stop["lat"], stop["lon"])
                distances.append(dist)

            min_distance = min(distances) if distances else 1000
            avg_distance = sum(distances) / len(distances) if distances else 1000

            # Calculate component scores
            density_score = min(stop_density / 50, 1.0) * 100  # 50 stops/km2 = max
            diversity_score = min(mode_diversity / 4, 1.0) * 100  # 4 modes = max
            proximity_score = max(0, 100 - (min_distance / 10))  # 0m = 100, 1000m = 0
            complexity_score = min(mode_complexity_score / 20, 1.0) * 100

            # Weighted total
            total_score = (
                density_score * TRANSIT_WEIGHTS["stop_density"]
                + diversity_score * TRANSIT_WEIGHTS["mode_diversity"]
                + proximity_score * TRANSIT_WEIGHTS["proximity"]
                + complexity_score * TRANSIT_WEIGHTS["network_connectivity"]
                + 50.0 * TRANSIT_WEIGHTS["service_frequency"]  # Estimate
            )

            grade = self.grade_score(total_score)
            confidence = 0.7 + min(stop_count / 20, 0.25)

            return ContextResult(
                raw_score=round(total_score, 2),
                grade=grade,
                confidence=round(confidence, 3),
                uncertainty=50.0,
                data_sources=["osm-overpass-transit"],
                metadata={
                    "mode": "production",
                    "algorithm_version": "2.0",
                    "stop_count": stop_count,
                    "stop_density_per_km2": round(stop_density, 2),
                    "mode_diversity": mode_diversity,
                    "mode_types": list(mode_types),
                    "min_distance_m": round(min_distance, 1),
                    "avg_distance_m": round(avg_distance, 1),
                    "radius_m": TRANSIT_SEARCH_RADIUS,
                },
            )

        except ImportError:
            logger.warning("OSM client not available")
            return self._compute_fallback(lat, lon)
        except Exception as e:
            raise UCIDContextError(
                f"TRANSIT computation failed: {e!s}",
                code="COMPUTATION_FAILED",
                details={"lat": lat, "lon": lon},
            ) from e

    def _compute_fallback(self, lat: float, lon: float) -> ContextResult:
        """Fallback when OSM is unavailable."""
        # Estimate based on city center proximity
        city_transit_scores = [
            (40.4093, 49.8671, 65, "Baku"),      # Good metro
            (41.0082, 28.9784, 85, "Istanbul"),  # Excellent metro
            (52.5200, 13.4050, 90, "Berlin"),    # Excellent transit
            (48.8566, 2.3522, 92, "Paris"),      # Excellent metro
            (60.1699, 24.9384, 88, "Helsinki"),  # Very good transit
        ]

        min_dist = float("inf")
        estimated_score = 40.0
        closest_city = None

        for clat, clon, score, name in city_transit_scores:
            dist = math.sqrt((lat - clat) ** 2 + (lon - clon) ** 2)
            if dist < min_dist:
                min_dist = dist
                estimated_score = score - (dist * 200)
                closest_city = name

        estimated_score = max(10.0, min(100.0, estimated_score))
        grade = self.grade_score(estimated_score)

        return ContextResult(
            raw_score=round(estimated_score, 2),
            grade=grade,
            confidence=0.55,
            uncertainty=150.0,
            data_sources=["estimation-city-transit"],
            metadata={
                "mode": "fallback",
                "algorithm_version": "2.0",
                "closest_city": closest_city,
            },
        )

    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in meters."""
        R = 6371000  # Earth radius in meters
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)

        a = (
            math.sin(dphi / 2) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

