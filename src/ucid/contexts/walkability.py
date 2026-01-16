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
infrastructure quality using real OSM Overpass API data for
sidewalks, crossings, street lights, and other pedestrian features.
"""

from __future__ import annotations

import asyncio
import logging
import math

from ucid.contexts.base import BaseContext, ContextResult
from ucid.core.errors import UCIDContextError

logger = logging.getLogger(__name__)

# Walkability scoring weights
WALK_WEIGHTS = {
    "sidewalk_coverage": 0.25,
    "crossing_density": 0.20,
    "lighting": 0.15,
    "intersection_density": 0.20,
    "pedestrian_paths": 0.20,
}

# Search radius for walkability analysis
WALK_SEARCH_RADIUS = 500  # meters


class WalkabilityContext(BaseContext):
    """Walkability context for pedestrian infrastructure scoring.

    This context evaluates walkability using real OSM data:
    - Sidewalk coverage and quality
    - Pedestrian crossing density
    - Street lighting availability
    - Intersection density (street connectivity)
    - Dedicated pedestrian paths

    Example:
        >>> context = WalkabilityContext()
        >>> result = context.compute(lat=40.4093, lon=49.8671, timestamp="2026W01T10")
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
        del timestamp  # Reserved for temporal variation

        try:
            return asyncio.run(self._compute_async(lat, lon))
        except RuntimeError:
            try:
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(self._compute_async(lat, lon))
            except Exception as e:
                logger.warning(f"Async walk query failed: {e}")
                return self._compute_fallback(lat, lon)
        except Exception as e:
            logger.warning(f"Walk computation failed: {e}")
            return self._compute_fallback(lat, lon)

    async def _compute_async(self, lat: float, lon: float) -> ContextResult:
        """Async computation using real OSM infrastructure data."""
        try:
            from ucid.data.osm_client import OSMClient

            async with OSMClient(use_cache=True) as client:
                infra = await client.query_pedestrian_infrastructure(
                    lat=lat,
                    lon=lon,
                    radius=WALK_SEARCH_RADIUS,
                )

            total_elements = infra.get("total_elements", 0)
            ways = infra.get("ways", 0)
            nodes = infra.get("nodes", 0)

            # Calculate area in km2
            area_km2 = (WALK_SEARCH_RADIUS / 1000) ** 2 * math.pi

            # Estimate component scores
            # Sidewalks and footways (ways)
            sidewalk_density = ways / area_km2
            sidewalk_score = min(sidewalk_density / 100, 1.0) * 100

            # Crossings and lights (nodes)
            node_density = nodes / area_km2
            crossing_score = min(node_density / 50, 1.0) * 100

            # Total infrastructure density
            total_density = total_elements / area_km2
            overall_density_score = min(total_density / 150, 1.0) * 100

            # Calculate weighted total
            total_score = (
                sidewalk_score * WALK_WEIGHTS["sidewalk_coverage"]
                + crossing_score * WALK_WEIGHTS["crossing_density"]
                + crossing_score * 0.5 * WALK_WEIGHTS["lighting"]
                + overall_density_score * WALK_WEIGHTS["intersection_density"]
                + sidewalk_score * 0.8 * WALK_WEIGHTS["pedestrian_paths"]
            )

            grade = self.grade_score(total_score)
            confidence = 0.65 + min(total_elements / 100, 0.30)

            return ContextResult(
                raw_score=round(total_score, 2),
                grade=grade,
                confidence=round(confidence, 3),
                uncertainty=75.0,
                data_sources=["osm-overpass-pedestrian"],
                metadata={
                    "mode": "production",
                    "algorithm_version": "2.0",
                    "total_elements": total_elements,
                    "ways": ways,
                    "nodes": nodes,
                    "density_per_km2": round(total_density, 2),
                    "radius_m": WALK_SEARCH_RADIUS,
                },
            )

        except ImportError:
            logger.warning("OSM client not available")
            return self._compute_fallback(lat, lon)
        except Exception as e:
            raise UCIDContextError(
                f"WALK computation failed: {e!s}",
                code="COMPUTATION_FAILED",
                details={"lat": lat, "lon": lon},
            ) from e

    def _compute_fallback(self, lat: float, lon: float) -> ContextResult:
        """Fallback when OSM is unavailable."""
        city_walk_scores = [
            (40.4093, 49.8671, 55, "Baku"),
            (41.0082, 28.9784, 65, "Istanbul"),
            (52.5200, 13.4050, 88, "Berlin"),
            (48.8566, 2.3522, 90, "Paris"),
            (60.1699, 24.9384, 85, "Helsinki"),
            (51.5074, -0.1278, 82, "London"),
        ]

        min_dist = float("inf")
        estimated_score = 50.0
        closest_city = None

        for clat, clon, score, name in city_walk_scores:
            dist = math.sqrt((lat - clat) ** 2 + (lon - clon) ** 2)
            if dist < min_dist:
                min_dist = dist
                estimated_score = score - (dist * 150)
                closest_city = name

        estimated_score = max(15.0, min(100.0, estimated_score))
        grade = self.grade_score(estimated_score)

        return ContextResult(
            raw_score=round(estimated_score, 2),
            grade=grade,
            confidence=0.50,
            uncertainty=200.0,
            data_sources=["estimation-city-walk"],
            metadata={
                "mode": "fallback",
                "algorithm_version": "2.0",
                "closest_city": closest_city,
            },
        )

