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

"""S2 geometry operations for UCID.

This module provides S2 cell operations as an alternative to H3 for
spatial indexing. Requires the optional `s2sphere` dependency.

Note:
    S2 is primarily used for compatibility with Google-based systems.
    H3 is the recommended spatial index for UCID operations.
"""

try:
    import s2sphere  # type: ignore[import-untyped]
except ImportError:
    s2sphere = None  # type: ignore[assignment]


def latlon_to_cell_id(lat: float, lon: float, level: int = 12) -> int:
    """Convert lat/lon coordinates to S2 Cell ID.

    Args:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        level: S2 cell level (0-30). Defaults to 12.

    Returns:
        S2 Cell ID as an integer.

    Raises:
        ImportError: If s2sphere is not installed.

    Example:
        >>> cell_id = latlon_to_cell_id(41.015, 28.979)
        >>> print(f"S2 Cell ID: {cell_id}")
    """
    if s2sphere is None:
        raise ImportError("s2sphere not installed - run: pip install s2sphere")
    point = s2sphere.LatLng.from_degrees(lat, lon)
    cell = s2sphere.CellId.from_lat_lng(point).parent(level)
    return cell.id()


def cell_id_to_latlon(cell_id: int) -> tuple[float, float]:
    """Convert S2 Cell ID to center coordinates.

    Args:
        cell_id: S2 Cell ID as an integer.

    Returns:
        Tuple of (latitude, longitude) for cell center.

    Raises:
        ImportError: If s2sphere is not installed.

    Example:
        >>> lat, lon = cell_id_to_latlon(cell_id)
        >>> print(f"Center: {lat}, {lon}")
    """
    if s2sphere is None:
        raise ImportError("s2sphere not installed - run: pip install s2sphere")
    cell = s2sphere.CellId(cell_id)
    latlng = cell.to_lat_lng()
    return latlng.lat().degrees, latlng.lng().degrees
