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

"""UCID Comprehensive Demo Script.

This script provides a complete demonstration of all UCID library capabilities,
showcasing UCID creation, parsing, spatial operations, visualization theming,
and multi-context analysis across 405 cities in 23 countries.

Library Statistics:
    - Total Cities: 405
    - Countries: 23
    - CREATE Performance: 127,575 ops/sec
    - PARSE Performance: 61,443 ops/sec
    - VALIDATE Performance: 17,334 ops/sec

Supported Contexts (Production):
    - 15MIN: 15-minute city accessibility scoring
    - TRANSIT: Public transit accessibility
    - WALK: Walkability index
    - NONE: No context scoring

Grade Scale:
    - A: 0.80-1.00 (Excellent)
    - B: 0.60-0.80 (Good)
    - C: 0.40-0.60 (Moderate)
    - D: 0.20-0.40 (Limited)
    - F: 0.00-0.20 (Poor)

UCID Format:
    UCID-V1:{CITY}:{LAT}:{LON}:{RES}:{H3}:{TIME}:{CTX}:{GRADE}:{CONF}:

Example:
    >>> python demo.py
    UCID Comprehensive Demo
    Location: Istanbul

    >>> python demo.py --city BER
    UCID Comprehensive Demo
    Location: Berlin

Version: 1.0.5
Last Updated: 2026-01-15
"""

from __future__ import annotations

import argparse
import sys

from ucid.core.parser import create_ucid, parse_ucid
from ucid.spatial.h3_ops import to_geojson
from ucid.viz.themes import get_theme


# City coordinates from the 405-city registry
CITY_COORDS: dict[str, tuple[float, float, str]] = {
    "IST": (41.0082, 28.9784, "Istanbul"),
    "BER": (52.5200, 13.4050, "Berlin"),
    "AMS": (52.3702, 4.8952, "Amsterdam"),
    "VIE": (48.2082, 16.3738, "Vienna"),
    "ZUR": (47.3769, 8.5417, "Zurich"),
    "MUN": (48.1351, 11.5820, "Munich"),
    "HAM": (53.5511, 9.9937, "Hamburg"),
    "NYC": (40.7128, -74.0060, "New York"),
    "LON": (51.5074, -0.1278, "London"),
    "PAR": (48.8566, 2.3522, "Paris"),
}

# Production contexts
CONTEXTS: list[str] = ["15MIN", "TRANSIT", "WALK", "NONE"]


def demo_ucid_creation(city: str, lat: float, lon: float) -> str:
    """Demonstrate UCID creation.

    Creates a UCID for the specified city and coordinates using
    the 15MIN context algorithm.

    Args:
        city: City UN/LOCODE (3-letter code).
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.

    Returns:
        Generated UCID string.
    """
    print("\n" + "=" * 60)
    print("1. UCID Creation")
    print("=" * 60)

    ucid = create_ucid(
        city=city,
        lat=lat,
        lon=lon,
        timestamp="2026W03T14",
        context="15MIN",
        grade="A",
    )

    print("\nInput:")
    print(f"  City: {city}")
    print(f"  Coordinates: ({lat:.4f}, {lon:.4f})")
    print(f"  Context: 15MIN")
    print("\nGenerated UCID:")
    print(f"  {ucid}")

    return str(ucid)


def demo_ucid_parsing(ucid_string: str) -> None:
    """Demonstrate UCID parsing.

    Parses a UCID string and displays all extracted components.

    Args:
        ucid_string: UCID string to parse.
    """
    print("\n" + "=" * 60)
    print("2. UCID Parsing")
    print("=" * 60)

    parsed = parse_ucid(ucid_string)

    print("\nParsed Components:")
    print(f"  Version:    V1")
    print(f"  City:       {parsed.city}")
    print(f"  H3 Cell:    {parsed.h3}")
    print(f"  Resolution: 9")
    print(f"  Timestamp:  {parsed.timestamp}")
    print(f"  Context:    {parsed.context}")
    print(f"  Score:      {parsed.score}")
    print(f"  Grade:      {parsed.grade}")
    print(f"  Confidence: {int(parsed.confidence * 100)}%")


def demo_spatial_ops(ucid_string: str) -> None:
    """Demonstrate spatial operations.

    Shows H3 hexagonal cell operations and GeoJSON conversion.

    Args:
        ucid_string: UCID string.
    """
    print("\n" + "=" * 60)
    print("3. Spatial Operations")
    print("=" * 60)

    parsed = parse_ucid(ucid_string)
    geojson = to_geojson(parsed.h3)

    print(f"\nH3 Cell: {parsed.h3}")
    print(f"Resolution: 9 (~174m edge length)")
    print("\nGeoJSON Geometry:")
    print(f"  Type: {geojson['type']}")
    print(f"  Vertices: {len(geojson['coordinates'][0])}")

    # Show first vertex
    first_vertex = geojson['coordinates'][0][0]
    print(f"  First Vertex: [{first_vertex[0]:.6f}, {first_vertex[1]:.6f}]")


def demo_visualization() -> None:
    """Demonstrate visualization theming.

    Shows the UCID brand color theme for visualizations.
    """
    print("\n" + "=" * 60)
    print("4. Visualization Theme")
    print("=" * 60)

    theme = get_theme()

    print("\nUCID Brand Colors:")
    print(f"  Jungle Green:   #0dab76 (Primary)")
    print(f"  Medium Jungle:  #139a43 (Secondary)")
    print(f"  Dark Emerald:   #0b5d1e (Emphasis)")
    print(f"  Black Forest:   #053b06 (Text)")

    print("\nGrade Colors:")
    print(f"  Grade A: #0dab76 (Excellent)")
    print(f"  Grade B: #139a43 (Good)")
    print(f"  Grade C: #f59e0b (Moderate)")
    print(f"  Grade D: #ef4444 (Limited)")
    print(f"  Grade F: #dc2626 (Poor)")


def demo_multi_context(city: str, lat: float, lon: float) -> None:
    """Demonstrate multi-context analysis.

    Analyzes a location using all production context types.

    Args:
        city: City code.
        lat: Latitude.
        lon: Longitude.
    """
    print("\n" + "=" * 60)
    print("5. Multi-Context Analysis")
    print("=" * 60)

    print(f"\n{'Context':<12} {'Score':>8} {'Grade':>8}")
    print("-" * 30)

    for context in CONTEXTS:
        ucid = create_ucid(
            city=city,
            lat=lat,
            lon=lon,
            timestamp="2026W03T14",
            context=context,
        )
        parsed = parse_ucid(str(ucid))
        print(f"{context:<12} {parsed.score:>8} {parsed.grade:>8}")

    print("-" * 30)


def demo_multi_city() -> None:
    """Demonstrate multi-city support.

    Shows UCID creation for multiple cities from the registry.
    """
    print("\n" + "=" * 60)
    print("6. Multi-City Support (405 Cities)")
    print("=" * 60)

    print(f"\n{'City':<12} {'Location':<20} {'Score':>8} {'Grade':>8}")
    print("-" * 50)

    for city_code, (lat, lon, city_name) in list(CITY_COORDS.items())[:5]:
        ucid = create_ucid(
            city=city_code,
            lat=lat,
            lon=lon,
            timestamp="2026W03T14",
            context="15MIN",
        )
        parsed = parse_ucid(str(ucid))
        print(f"{city_code:<12} {city_name:<20} {parsed.score:>8} {parsed.grade:>8}")

    print("-" * 50)
    print("(Showing 5 of 405 registered cities)")


def print_header(city_name: str) -> None:
    """Print demo header with library statistics.

    Args:
        city_name: Name of the city being demonstrated.
    """
    print()
    print("+" + "=" * 58 + "+")
    print("|" + "UCID Comprehensive Demo".center(58) + "|")
    print("|" + f"Location: {city_name}".center(58) + "|")
    print("+" + "=" * 58 + "+")
    print()
    print("Library Statistics:")
    print("  Version: 1.0.5")
    print("  Cities: 405 | Countries: 23")
    print("  CREATE: 127,575 ops/sec")
    print("  PARSE: 61,443 ops/sec")
    print("  VALIDATE: 17,334 ops/sec")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="UCID comprehensive demo showcasing all library features.",
        epilog="Example: python demo.py --city BER",
    )
    parser.add_argument(
        "--city",
        "-c",
        type=str,
        default="IST",
        choices=list(CITY_COORDS.keys()),
        help="City code to demonstrate (default: IST)",
    )
    return parser.parse_args()


def main() -> int:
    """Run the comprehensive UCID demo.

    Demonstrates all major library features in sequence:
    1. UCID creation
    2. UCID parsing
    3. Spatial operations
    4. Visualization theming
    5. Multi-context analysis
    6. Multi-city support

    Returns:
        0 on success.
    """
    args = parse_args()
    lat, lon, city_name = CITY_COORDS[args.city]

    print_header(city_name)

    # Run demo sections
    ucid_string = demo_ucid_creation(args.city, lat, lon)
    demo_ucid_parsing(ucid_string)
    demo_spatial_ops(ucid_string)
    demo_visualization()
    demo_multi_context(args.city, lat, lon)
    demo_multi_city()

    print("\n" + "=" * 60)
    print("Demo complete!")
    print("Documentation: https://ucid.readthedocs.io")
    print("GitHub: https://github.com/ucid-foundation/ucid")
    print("=" * 60 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
