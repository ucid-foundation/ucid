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

"""H3 spatial indexing operations.

This module provides utility functions for working with H3 hexagonal
hierarchical spatial indexes, supporting both h3-py v3 and v4 APIs.
"""

import h3
from shapely.geometry import Polygon  # type: ignore[import-untyped]


def get_resolution(h3_index: str) -> int:
    """Get the resolution level of an H3 index.

    Args:
        h3_index: H3 cell index as hexadecimal string.

    Returns:
        Resolution level (0-15).
    """
    if hasattr(h3, "get_resolution"):
        return h3.get_resolution(h3_index)
    return h3.h3_get_resolution(h3_index)


def k_ring(h3_index: str, k: int) -> list[str]:
    """Get k-ring neighbors of an H3 cell.

    Args:
        h3_index: Center H3 cell index.
        k: Ring distance.

    Returns:
        List of H3 indices in the k-ring.
    """
    if hasattr(h3, "grid_disk"):
        return list(h3.grid_disk(h3_index, k))
    return list(h3.k_ring(h3_index, k))


def cell_to_boundary(h3_index: str) -> Polygon:
    """Get the boundary polygon of an H3 cell.

    Args:
        h3_index: H3 cell index.

    Returns:
        Shapely Polygon representing the cell boundary.
    """
    coords = h3.cell_to_boundary(h3_index) if hasattr(h3, "cell_to_boundary") else h3.h3_to_geo_boundary(h3_index)

    # H3 returns (lat, lon), Shapely expects (lon, lat)
    swapped = [(c[1], c[0]) for c in coords]
    return Polygon(swapped)


def latlng_to_cell(lat: float, lon: float, resolution: int) -> str:
    """Convert lat/lng to H3 cell index.

    Args:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        resolution: H3 resolution level (0-15).

    Returns:
        H3 cell index as hexadecimal string.
    """
    if hasattr(h3, "latlng_to_cell"):
        return h3.latlng_to_cell(lat, lon, resolution)
    return h3.geo_to_h3(lat, lon, resolution)


def cell_to_latlng(h3_index: str) -> tuple[float, float]:
    """Get the center coordinates of an H3 cell.

    Args:
        h3_index: H3 cell index.

    Returns:
        Tuple of (latitude, longitude).
    """
    if hasattr(h3, "cell_to_latlng"):
        return h3.cell_to_latlng(h3_index)
    return h3.h3_to_geo(h3_index)
