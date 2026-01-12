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

"""Geohash operations for UCID spatial indexing.

This module provides functions for encoding and decoding Geohash
spatial indices. Requires the optional `pygeohash` dependency.
"""

try:
    import pygeohash as pgh  # type: ignore[import-untyped]
except ImportError:
    pgh = None  # type: ignore[assignment]


def encode(lat: float, lon: float, precision: int = 9) -> str:
    """Encode latitude/longitude to a Geohash string.

    Args:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        precision: Geohash precision (1-12). Higher = more precise.
            Defaults to 9 (~4.77m x 4.77m).

    Returns:
        Geohash string.

    Raises:
        ImportError: If pygeohash is not installed.

    Example:
        >>> geohash = encode(41.015, 28.979)
        >>> print(geohash)  # e.g., "sxk9g3tgr"
    """
    if pgh is None:
        raise ImportError("pygeohash not installed - run: pip install pygeohash")
    return pgh.encode(lat, lon, precision)


def decode(geohash: str) -> tuple[float, float]:
    """Decode a Geohash string to latitude/longitude.

    Args:
        geohash: Geohash string to decode.

    Returns:
        Tuple of (latitude, longitude).

    Raises:
        ImportError: If pygeohash is not installed.

    Example:
        >>> lat, lon = decode("sxk9g3tgr")
    """
    if pgh is None:
        raise ImportError("pygeohash not installed - run: pip install pygeohash")
    result = pgh.decode(geohash)
    return (float(result[0]), float(result[1]))


def neighbors(geohash: str) -> list[str]:
    """Get the 8 neighboring Geohashes.

    Args:
        geohash: Center Geohash string.

    Returns:
        List of 8 neighboring Geohash strings.

    Raises:
        ImportError: If pygeohash is not installed.
    """
    if pgh is None:
        raise ImportError("pygeohash not installed - run: pip install pygeohash")
    return list(pgh.neighbors(geohash))
