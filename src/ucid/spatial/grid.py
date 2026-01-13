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

"""Grid scanning utilities for UCID.

This module provides functions for generating H3 grids over geographic
areas and scanning cities systematically.
"""

from collections.abc import Generator

import h3

from ucid.core.constants import DEFAULT_H3_RESOLUTION
from ucid.core.models import UCID
from ucid.core.parser import create_ucid


def generate_grid_h3(
    min_lat: float,
    min_lon: float,
    max_lat: float,
    max_lon: float,
    resolution: int = DEFAULT_H3_RESOLUTION,
) -> list[str]:
    """Generate H3 cells covering a bounding box.

    Args:
        min_lat: Minimum latitude.
        min_lon: Minimum longitude.
        max_lat: Maximum latitude.
        max_lon: Maximum longitude.
        resolution: H3 resolution level (0-15).

    Returns:
        List of H3 cell indices covering the bounding box.
    """
    geojson = {
        "type": "Polygon",
        "coordinates": [
            [
                (min_lon, min_lat),
                (max_lon, min_lat),
                (max_lon, max_lat),
                (min_lon, max_lat),
                (min_lon, min_lat),
            ]
        ],
    }

    try:
        if hasattr(h3, "polyfill"):
            return list(h3.polyfill(geojson, resolution, geo_json_conformant=True))
    except Exception:
        pass

    return []


def scan_city_grid(
    city_code: str,
    bbox: tuple[float, float, float, float],
    resolution: int = DEFAULT_H3_RESOLUTION,
    timestamp: str = "2026W01T12",
    context: str = "15MIN",
) -> Generator[UCID, None, None]:
    """Generate UCID objects for an entire grid over a city.

    Args:
        city_code: 3-character city code.
        bbox: Bounding box as (min_lat, min_lon, max_lat, max_lon).
        resolution: H3 resolution level.
        timestamp: Temporal key for all generated UCIDs.
        context: Context identifier for all generated UCIDs.

    Yields:
        UCID objects for each cell in the grid.
    """
    cells = generate_grid_h3(*bbox, resolution)

    for h3_index in cells:
        if hasattr(h3, "cell_to_latlng"):
            lat, lon = h3.cell_to_latlng(h3_index)
        else:
            lat, lon = h3.h3_to_geo(h3_index)

        yield create_ucid(
            city=city_code,
            lat=lat,
            lon=lon,
            h3_res=resolution,
            h3_index=h3_index,
            timestamp=timestamp,
            context=context,
        )
