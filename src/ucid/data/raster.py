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

"""Raster data handling for UCID climate and environmental analysis.

This module provides functions for loading and extracting values from
raster datasets such as satellite imagery, elevation models, and
climate data. Requires the optional `rasterio` dependency.
"""

from typing import Any

try:
    import rasterio  # type: ignore[import-untyped]
except ImportError:
    rasterio = None  # type: ignore[assignment]


def load_raster(path: str) -> Any:
    """Load a raster file for reading.

    Opens a raster file using rasterio and returns the dataset object.
    The caller is responsible for closing the dataset or using it as
    a context manager.

    Args:
        path: Path to the raster file (GeoTIFF, COG, etc.).

    Returns:
        An open rasterio dataset object.

    Raises:
        ImportError: If rasterio is not installed.

    Example:
        >>> with load_raster("elevation.tif") as src:
        ...     data = src.read(1)
    """
    if rasterio is None:
        raise ImportError("rasterio not installed - run: pip install rasterio")
    return rasterio.open(path)


def extract_value(raster_path: str, lat: float, lon: float) -> float | None:
    """Extract a single value from a raster at given coordinates.

    Reads the value at the specified geographic coordinates from the
    first band of the raster file.

    Args:
        raster_path: Path to the raster file.
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.

    Returns:
        The raster value at the specified coordinates, or None if
        rasterio is not installed.

    Note:
        This function opens and closes the raster for each call.
        For batch operations, use load_raster() directly.

    Example:
        >>> elevation = extract_value("dem.tif", 41.015, 28.979)
        >>> print(f"Elevation: {elevation}m")
    """
    if rasterio is None:
        return None

    with rasterio.open(raster_path) as src:
        # Transform lat/lon to row/col using the raster's transform
        row, col = src.index(lon, lat)
        data = src.read(1)
        return float(data[row, col])
