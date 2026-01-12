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

"""Geometric operations for UCID spatial analysis.

This module provides functions for creating and manipulating
geometric objects using Shapely.
"""

from shapely.geometry import Point, Polygon, box  # type: ignore[import-untyped]

# Approximate meters per degree at equator
METERS_PER_DEGREE = 111000.0


def create_point(lat: float, lon: float) -> Point:
    """Create a Shapely Point geometry.

    Args:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.

    Returns:
        Shapely Point object.

    Note:
        Shapely uses (x, y) order, so lon comes before lat.

    Example:
        >>> point = create_point(41.015, 28.979)
    """
    return Point(lon, lat)


def create_bbox(
    min_lat: float,
    min_lon: float,
    max_lat: float,
    max_lon: float,
) -> Polygon:
    """Create a bounding box Polygon.

    Args:
        min_lat: Minimum latitude.
        min_lon: Minimum longitude.
        max_lat: Maximum latitude.
        max_lon: Maximum longitude.

    Returns:
        Shapely Polygon representing the bounding box.

    Example:
        >>> bbox = create_bbox(40.0, 28.0, 42.0, 30.0)
    """
    return box(min_lon, min_lat, max_lon, max_lat)


def buffer_point(lat: float, lon: float, distance_m: float) -> Polygon:
    """Create a circular buffer around a point.

    Args:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        distance_m: Buffer radius in meters.

    Returns:
        Shapely Polygon representing the buffered area.

    Note:
        This uses a simple approximation that assumes 1 degree ≈ 111km.
        For precise calculations, use a projected CRS.

    Example:
        >>> buffer = buffer_point(41.015, 28.979, 500)  # 500m buffer
    """
    delta = distance_m / METERS_PER_DEGREE
    return create_point(lat, lon).buffer(delta)


def point_in_polygon(lat: float, lon: float, polygon: Polygon) -> bool:
    """Check if a point is inside a polygon.

    Args:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        polygon: Shapely Polygon to test against.

    Returns:
        True if the point is inside the polygon.
    """
    point = create_point(lat, lon)
    return polygon.contains(point)
