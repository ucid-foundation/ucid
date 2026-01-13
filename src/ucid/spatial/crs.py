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

"""Coordinate Reference System (CRS) transformations for UCID.

This module provides functions for coordinate transformations
and distance calculations.
"""

import math

# Earth's radius in meters (WGS84 semi-major axis)
EARTH_RADIUS_METERS = 6378137.0


class CRSops:
    """Operations for Coordinate Reference Systems.

    Provides static methods for coordinate transformations and
    distance calculations.
    """

    @staticmethod
    def to_web_mercator(lat: float, lon: float) -> tuple[float, float]:
        """Convert lat/lon (EPSG:4326) to Web Mercator (EPSG:3857).

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.

        Returns:
            Tuple of (x, y) in meters.

        Example:
            >>> x, y = CRSops.to_web_mercator(41.015, 28.979)
        """
        x = EARTH_RADIUS_METERS * math.radians(lon)
        scale = x / lon if lon != 0 else EARTH_RADIUS_METERS * math.pi / 180
        y = 180.0 / math.pi * math.log(math.tan(math.pi / 4.0 + lat * (math.pi / 180.0) / 2.0)) * scale
        return x, y

    @staticmethod
    def haversine_distance(
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float,
    ) -> float:
        """Calculate great-circle distance using Haversine formula.

        Args:
            lat1: Latitude of first point in decimal degrees.
            lon1: Longitude of first point in decimal degrees.
            lat2: Latitude of second point in decimal degrees.
            lon2: Longitude of second point in decimal degrees.

        Returns:
            Distance in meters.

        Example:
            >>> dist = CRSops.haversine_distance(41.015, 28.979, 41.020, 28.985)
            >>> print(f"{dist:.0f} meters")
        """
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = math.sin(delta_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return EARTH_RADIUS_METERS * c
