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

"""GeoJSON input/output operations.

This module provides functions for exporting UCID data in GeoJSON format.
"""

import json

from ucid.core.models import UCID


def export_geojson(ucids: list[UCID], output_path: str) -> None:
    """Export UCIDs to GeoJSON FeatureCollection format.

    Args:
        ucids: List of UCID objects to export.
        output_path: Path to output GeoJSON file.

    Example:
        >>> ucids = [create_ucid(city="IST", lat=41.015, lon=28.979, ...)]
        >>> export_geojson(ucids, "output.geojson")
    """
    features = []
    for u in ucids:
        feature = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [u.lon, u.lat],
            },
            "properties": {
                "ucid": str(u),
                "city": u.city,
                "grade": u.grade,
                "confidence": u.confidence,
                "context": u.context,
                "timestamp": u.timestamp,
                "h3_index": u.h3_index,
            },
        }
        features.append(feature)

    collection = {
        "type": "FeatureCollection",
        "features": features,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(collection, f, indent=2)
