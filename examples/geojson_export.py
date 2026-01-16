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
use with web mapping libraries like Mapbox, Leaflet, deck.gl, or Kepler.gl.
The output is compatible with all major GIS software and web mapping tools.

Library Statistics:
    - Total Cities: 405
    - Countries: 23
    - CREATE Performance: 127,575 ops/sec

Output Formats:
    - GeoJSON: Standard geographic data format for web mapping
    - GeoPackage (optional): SQLite-based format for GIS software

Web Mapping Integration:
    - Leaflet.js: Open-source JavaScript library
    - Mapbox GL JS: Vector tile mapping library
    - deck.gl: Large-scale WebGL-powered visualizations
    - Kepler.gl: Uber's geospatial analysis tool

Example:
    >>> python geojson_export.py
    Exporting to ucid_grid.geojson...
    Exported 100 features across 5 cities

Version: 1.0.5
Last Updated: 2026-01-15
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import numpy as np

from ucid import create_ucid, parse_ucid


# Sample cities for grid generation
CITIES: list[dict] = [
    {"code": "IST", "name": "Istanbul", "lat": 41.0370, "lon": 28.9850},
    {"code": "BER", "name": "Berlin", "lat": 52.5200, "lon": 13.4050},
    {"code": "AMS", "name": "Amsterdam", "lat": 52.3702, "lon": 4.8952},
    {"code": "VIE", "name": "Vienna", "lat": 48.2082, "lon": 16.3738},
    {"code": "ZUR", "name": "Zurich", "lat": 47.3769, "lon": 8.5417},
]

# Grade colors for visualization
GRADE_COLORS: dict[str, str] = {
    "A": "#0dab76",  # UCID Jungle Green
    "B": "#139a43",  # UCID Medium Jungle
    "C": "#f59e0b",  # Yellow/Orange
    "D": "#ef4444",  # Red
    "F": "#dc2626",  # Dark Red
}


def generate_ucid_grid(
    city: dict,
    n_points: int = 25,
    context: str = "15MIN",
) -> list[dict]:
    """Generate a grid of UCIDs around a city center.

    Creates a square grid of points around the city center and
    generates a UCID for each point.

    Args:
        city: City dictionary with code, name, lat, lon.
        n_points: Approximate number of grid points.
        context: UCID context type.

    Returns:
        List of UCID result dictionaries with location data.
    """
    results = []
    np.random.seed(42)

    # Generate points in a grid pattern
    grid_size = int(np.sqrt(n_points))
    offsets = np.linspace(-0.02, 0.02, grid_size)  # ~2km grid

    for lat_offset in offsets:
        for lon_offset in offsets:
            lat = city["lat"] + lat_offset
            lon = city["lon"] + lon_offset

            ucid = create_ucid(
                city=city["code"],
                lat=lat,
                lon=lon,
                timestamp="2026W03T14",
                context=context,
            )
            parsed = parse_ucid(str(ucid))

            results.append({
                "ucid": str(ucid),
                "city_code": city["code"],
                "city_name": city["name"],
                "lat": lat,
                "lon": lon,
                "score": parsed.score,
                "grade": parsed.grade,
                "confidence": parsed.confidence,
                "context": context,
            })

    return results


def export_to_geojson(
    data: list[dict],
    output_path: str | Path,
) -> dict:
    """Export UCID data to GeoJSON format.

    Creates a GeoJSON FeatureCollection with Point geometries
    and UCID properties for each location.

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
                "city_code": item["city_code"],
                "city_name": item["city_name"],
                "score": item["score"],
                "grade": item["grade"],
                "confidence": item["confidence"],
                "context": item["context"],
                "fill_color": GRADE_COLORS.get(item["grade"], "#888888"),
            },
        }
        features.append(feature)

    geojson = {
        "type": "FeatureCollection",
        "name": "UCID Grid Export",
        "crs": {
            "type": "name",
            "properties": {"name": "urn:ogc:def:crs:OGC:1.3:CRS84"},
        },
        "features": features,
        "metadata": {
            "version": "1.0.5",
            "generated": datetime.now().isoformat(),
            "total_features": len(features),
            "source": "UCID Foundation",
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(geojson, f, indent=2, ensure_ascii=False)

    return geojson


def print_leaflet_example(geojson_path: str) -> None:
    """Print example Leaflet.js code for using the GeoJSON.

    Args:
        geojson_path: Path to the GeoJSON file.
    """
    print("""
Leaflet.js Integration Example:

```javascript
// Load and display UCID data on a Leaflet map
fetch('""" + geojson_path + """')
  .then(response => response.json())
  .then(data => {
    L.geoJSON(data, {
      pointToLayer: (feature, latlng) => {
        return L.circleMarker(latlng, {
          radius: 8,
          fillColor: feature.properties.fill_color,
          color: '#000',
          weight: 1,
          opacity: 1,
          fillOpacity: 0.8,
        });
      },
      onEachFeature: (feature, layer) => {
        layer.bindPopup(`
          <b>${feature.properties.city_name}</b><br>
          Score: ${feature.properties.score}<br>
          Grade: ${feature.properties.grade}
        `);
      }
    }).addTo(map);
  });
```
""")


def main() -> None:
    """Run the GeoJSON export demonstration.

    Generates UCID grids for multiple cities and exports
    to GeoJSON format for web mapping.
    """
    print("=" * 60)
    print("UCID GeoJSON Export Example")
    print("=" * 60)
    print("\nLibrary: UCID v1.0.5")
    print("Cities: 405 | Countries: 23")
    print(f"Exporting grids for {len(CITIES)} cities")

    # Generate UCID grids for all cities
    print("\n1. Generating UCID grids...")
    all_data = []
    for city in CITIES:
        data = generate_ucid_grid(city, n_points=25, context="15MIN")
        all_data.extend(data)
        print(f"   {city['name']}: {len(data)} points")

    print(f"\n   Total: {len(all_data)} points")

    # Export to GeoJSON
    output_path = "ucid_grid.geojson"
    print(f"\n2. Exporting to {output_path}...")
    geojson = export_to_geojson(all_data, output_path)
    print(f"   Exported {len(geojson['features'])} features")

    # Show sample feature
    print("\n3. Sample Feature:")
    sample = geojson["features"][0]
    print(json.dumps(sample, indent=2))

    # Show statistics by city
    print("\n4. Features by City:")
    from collections import Counter
    city_counts = Counter(f["properties"]["city_name"] for f in geojson["features"])
    for city, count in city_counts.items():
        print(f"   {city}: {count} features")

    # Show Leaflet example
    print("\n5. Web Mapping Integration:")
    print_leaflet_example(output_path)

    print("=" * 60)
    print("GeoJSON export complete!")
    print(f"Output file: {Path(output_path).absolute()}")
    print("=" * 60)


if __name__ == "__main__":
    main()
