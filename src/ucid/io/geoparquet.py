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

"""GeoParquet input/output operations.

This module provides functions for exporting and importing UCID data
in GeoParquet format, the recommended format for large-scale spatial data.
"""

from typing import Any

from ucid.core.errors import UCIDError
from ucid.core.models import UCID

try:
    import geopandas as gpd  # type: ignore[import-untyped]
    from shapely.geometry import Point  # type: ignore[import-untyped]

    _HAS_GEOPANDAS = True
except ImportError:
    gpd = None  # type: ignore[assignment]
    Point = None  # type: ignore[assignment]
    _HAS_GEOPANDAS = False


def export_geoparquet(ucids: list[UCID], output_path: str) -> None:
    """Export a list of UCIDs to GeoParquet format.

    Args:
        ucids: List of UCID objects to export.
        output_path: Path to output GeoParquet file.

    Raises:
        UCIDError: If GeoPandas is not installed.

    Example:
        >>> export_geoparquet(ucids, "output.parquet")
    """
    if not _HAS_GEOPANDAS:
        raise UCIDError(
            "GeoPandas is required for GeoParquet export. Install with: pip install UCID[contexts]",
            code="MISSING_DEPENDENCY",
        )

    data = [
        {
            "ucid": str(u),
            "city": u.city,
            "grade": u.grade,
            "confidence": u.confidence,
            "context": u.context,
            "timestamp": u.timestamp,
            "h3_index": u.h3_index,
            "geometry": Point(u.lon, u.lat),
        }
        for u in ucids
    ]

    gdf = gpd.GeoDataFrame(data, crs="EPSG:4326")
    gdf.to_parquet(output_path)


def read_geoparquet(input_path: str) -> Any:
    """Read a GeoParquet file.

    Args:
        input_path: Path to GeoParquet file.

    Returns:
        GeoDataFrame with the data.

    Raises:
        UCIDError: If GeoPandas is not installed.

    Example:
        >>> gdf = read_geoparquet("data.parquet")
        >>> print(gdf.head())
    """
    if not _HAS_GEOPANDAS:
        raise UCIDError(
            "GeoPandas is required for GeoParquet import. Install with: pip install UCID[contexts]",
            code="MISSING_DEPENDENCY",
        )

    return gpd.read_parquet(input_path)
