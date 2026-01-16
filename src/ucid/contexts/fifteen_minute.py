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

"""15-Minute City context implementation.

This module implements the 15-Minute City context, which evaluates walkable
access to essential amenities (grocery, healthcare, education, parks, etc.)
within a 15-minute walking radius.

The algorithm uses real OSM Overpass API data:
1. Query POIs within walking distance (1200m for 15 min at 5km/h)
2. Calculate coverage for each amenity category
3. Apply weighted scoring based on essential services
4. Return calibrated score with confidence

Example:
    >>> context = FifteenMinuteContext()
    >>> result = context.compute(lat=41.015, lon=28.979, timestamp="2026W01T12")
    >>> print(f"Score: {result.raw_score}, Grade: {result.grade}")
"""

from __future__ import annotations

import asyncio
import logging
import math
from typing import Any

from ucid.contexts.base import BaseContext, ContextResult
from ucid.core.errors import UCIDContextError

logger = logging.getLogger(__name__)

# Amenity weights for 15-minute city scoring
AMENITY_WEIGHTS = {
    "grocery": 0.20,       # Essential for daily needs
    "healthcare": 0.15,    # Medical access
    "education": 0.15,     # Schools and learning
    "recreation": 0.10,    # Parks and leisure
    "food": 0.10,          # Restaurants and cafes
    "transport": 0.15,     # Transit access
    "finance": 0.05,       # Banks and ATMs
    "childcare": 0.10,     # Childcare facilities
}

# Minimum POIs needed for full score in each category
MIN_POIS_FOR_FULL_SCORE = {
    "grocery": 3,
    "healthcare": 2,
    "education": 2,
    "recreation": 2,
    "food": 5,
    "transport": 3,
    "finance": 1,
    "childcare": 1,
}

# Walking distance for 15 minutes at 5 km/h
WALKING_RADIUS_METERS = 1250


class FifteenMinuteContext(BaseContext):
    """15-Minute City context for walkable accessibility scoring.

    This context evaluates how well a location meets the 15-minute city
    paradigm, where residents can access essential services within a
    15-minute walk. Uses real OSM Overpass API data.

    Attributes:
        config: Configuration dictionary with optional keys:
            - amenity_weights: Dict mapping amenity types to importance weights
            - walk_speed_kmh: Walking speed in km/h (default: 5.0)
            - max_time_minutes: Maximum walking time (default: 15)
            - use_cache: Whether to cache OSM queries (default: True)

    Example:
        >>> context = FifteenMinuteContext()
        >>> result = context.compute(lat=40.4093, lon=49.8671, timestamp="2026W01T12")
        >>> print(f"Score: {result.raw_score}, Grade: {result.grade}")
    """

    @property
    def context_id(self) -> str:
        """Return the unique identifier for this context."""
        return "15MIN"

    def compute(
        self,
        lat: float,
        lon: float,
        timestamp: str,
    ) -> ContextResult:
        """Compute 15-minute accessibility score for a location.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            timestamp: Temporal key (YYYYWwwThh format).

        Returns:
            ContextResult with accessibility score and metadata.

        Raises:
            UCIDContextError: If computation fails.
        """
        del timestamp  # Reserved for temporal weighting

        try:
            # Use asyncio to run the async OSM query
            return asyncio.get_event_loop().run_until_complete(
                self._compute_async(lat, lon)
            )
        except RuntimeError:
            # No event loop running, create one
            return asyncio.run(self._compute_async(lat, lon))
        except Exception as e:
            logger.warning(f"OSM query failed, using fallback: {e}")
            return self._compute_fallback(lat, lon)

    async def _compute_async(self, lat: float, lon: float) -> ContextResult:
        """Async computation using real OSM data.

        Args:
            lat: Latitude.
            lon: Longitude.

        Returns:
            ContextResult with real data.
        """
        try:
            from ucid.data.osm_client import OSMClient, POI_CATEGORIES

            async with OSMClient(use_cache=True) as client:
                pois = await client.query_amenities(
                    lat=lat,
                    lon=lon,
                    radius=WALKING_RADIUS_METERS,
                    categories=list(AMENITY_WEIGHTS.keys()),
                )

            # Count POIs by category
            category_counts: dict[str, int] = {cat: 0 for cat in AMENITY_WEIGHTS}

            for poi in pois:
                poi_type = poi.get("type", "")
                for category, types in POI_CATEGORIES.items():
                    if poi_type in types and category in category_counts:
                        category_counts[category] += 1
                        break

            # Calculate weighted score
            total_score = 0.0
            category_scores: dict[str, float] = {}

            for category, weight in AMENITY_WEIGHTS.items():
                count = category_counts.get(category, 0)
                min_needed = MIN_POIS_FOR_FULL_SCORE.get(category, 1)

                # Score is proportional to min(count/min_needed, 1.0)
                cat_score = min(count / min_needed, 1.0) * 100
                category_scores[category] = cat_score
                total_score += cat_score * weight

            # Determine grade
            grade = self.grade_score(total_score)

            # Calculate confidence based on data availability
            categories_with_data = sum(1 for c in category_counts.values() if c > 0)
            confidence = 0.5 + (categories_with_data / len(AMENITY_WEIGHTS)) * 0.45

            return ContextResult(
                raw_score=round(total_score, 2),
                grade=grade,
                confidence=round(confidence, 3),
                uncertainty=WALKING_RADIUS_METERS / 10,
                data_sources=["osm-overpass"],
                metadata={
                    "mode": "production",
                    "algorithm_version": "2.0",
                    "total_pois": len(pois),
                    "category_counts": category_counts,
                    "category_scores": category_scores,
                    "radius_meters": WALKING_RADIUS_METERS,
                },
            )

        except ImportError:
            logger.warning("OSM client not available, using fallback")
            return self._compute_fallback(lat, lon)
        except Exception as e:
            raise UCIDContextError(
                f"15MIN computation failed: {e!s}",
                code="COMPUTATION_FAILED",
                details={"lat": lat, "lon": lon, "error": str(e)},
            ) from e

    def _compute_fallback(self, lat: float, lon: float) -> ContextResult:
        """Fallback computation when OSM is unavailable.

        Uses a simple model based on city center proximity.

        Args:
            lat: Latitude.
            lon: Longitude.

        Returns:
            ContextResult with estimated score.
        """
        # Known city centers for better estimation
        city_centers = [
            (40.4093, 49.8671, "Baku"),
            (41.0082, 28.9784, "Istanbul"),
            (52.5200, 13.4050, "Berlin"),
            (48.8566, 2.3522, "Paris"),
            (60.1699, 24.9384, "Helsinki"),
        ]

        # Find closest city center
        min_dist = float("inf")
        closest_city = None

        for clat, clon, cname in city_centers:
            dist = math.sqrt((lat - clat) ** 2 + (lon - clon) ** 2)
            if dist < min_dist:
                min_dist = dist
                closest_city = cname

        # Score based on distance from center
        # Within 0.05 degrees (~5km) = high score
        if min_dist < 0.05:
            raw_score = 85.0 - (min_dist * 500)
        elif min_dist < 0.1:
            raw_score = 70.0 - ((min_dist - 0.05) * 400)
        elif min_dist < 0.2:
            raw_score = 50.0 - ((min_dist - 0.1) * 200)
        else:
            raw_score = max(20.0, 30.0 - (min_dist * 50))

        raw_score = max(0.0, min(100.0, raw_score))
        grade = self.grade_score(raw_score)

        return ContextResult(
            raw_score=round(raw_score, 2),
            grade=grade,
            confidence=0.60,  # Lower confidence for fallback
            uncertainty=200.0,
            data_sources=["estimation-city-proximity"],
            metadata={
                "mode": "fallback",
                "algorithm_version": "2.0",
                "closest_city": closest_city,
                "distance_degrees": round(min_dist, 4),
            },
        )

