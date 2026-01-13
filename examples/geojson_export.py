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

"""UCID GeoJSON Export Example.

This script demonstrates how to export UCID data to GeoJSON format for
use with web mapping libraries like Mapbox, Leaflet, or deck.gl.

Example:
    >>> python geojson_export.py
    Exporting to ucid_grid.geojson...
    Exported 25 features
"""

import json

import numpy as np

from ucid import create_ucid, parse_ucid


def generate_ucid_grid(
    center_lat: float,
    center_lon: float,
    n_points: int = 25,
) -> list[dict]:
    """Generate a grid of UCIDs around a center point.

    Args:
        center_lat: Center latitude.
        center_lon: Center longitude.
        n_points: Number of grid points.

    Returns:
        List of UCID result dictionaries.
    """
    results = []
    np.random.seed(42)

    # Generate points in a grid pattern
    grid_size = int(np.sqrt(n_points))
    offsets = np.linspace(-0.02, 0.02, grid_size)

    for lat_offset in offsets:
        for lon_offset in offsets:
            lat = center_lat + lat_offset
            lon = center_lon + lon_offset

            ucid = create_ucid(
                city="IST",
                lat=lat,
                lon=lon,
                timestamp="2026W02T14",
                context="15MIN",
            )
            parsed = parse_ucid(str(ucid))

            results.append(
                {
                    "ucid": str(ucid),
                    "lat": lat,
                    "lon": lon,
                    "score": parsed.score,
                    "grade": parsed.grade,
                }
            )

    return results


def export_to_geojson(data: list[dict], output_path: str) -> dict:
    """Export UCID data to GeoJSON format.

    Args:
        data: List of UCID result dictionaries.
        output_path: Output file path.

    Returns:
        GeoJSON dictionary.
    """
    features = []

    for item in data:
        feature = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [item["lon"], item["lat"]],
            },
            "properties": {
                "ucid": item["ucid"],
                "score": item["score"],
                "grade": item["grade"],
            },
        }
        features.append(feature)

    geojson = {
        "type": "FeatureCollection",
        "features": features,
    }

    with open(output_path, "w") as f:
        json.dump(geojson, f, indent=2)

    return geojson


def main() -> None:
    """Run the GeoJSON export demonstration."""
    print("=" * 60)
    print("UCID GeoJSON Export Example")
    print("=" * 60)

    # Generate UCID grid
    print("\n1. Generating UCID grid around Taksim Square...")
    data = generate_ucid_grid(41.0370, 28.9850, n_points=25)
    print(f"   Generated {len(data)} UCIDs")

    # Export to GeoJSON
    output_path = "ucid_grid.geojson"
    print(f"\n2. Exporting to {output_path}...")
    geojson = export_to_geojson(data, output_path)
    print(f"   Exported {len(geojson['features'])} features")

    # Show sample
    print("\n3. Sample Feature:")
    print(json.dumps(geojson["features"][0], indent=2))

    print("\n" + "=" * 60)
    print("GeoJSON export complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
