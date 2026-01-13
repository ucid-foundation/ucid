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

This script provides a complete demonstration of UCID library capabilities,
showcasing all major features including UCID creation, parsing, spatial
operations, visualization theming, and multi-context analysis.

Example:
    >>> python demo.py
    UCID Comprehensive Demo
    Location: Istanbul
"""

from __future__ import annotations

import argparse
import sys

from ucid.core.parser import create_ucid, parse_ucid
from ucid.spatial.h3_ops import to_geojson
from ucid.viz.themes import get_theme

# City coordinates
CITY_COORDS: dict[str, tuple[float, float, str]] = {
    "IST": (41.0082, 28.9784, "Istanbul"),
    "NYC": (40.7128, -74.0060, "New York"),
    "LON": (51.5074, -0.1278, "London"),
    "PAR": (48.8566, 2.3522, "Paris"),
    "TYO": (35.6762, 139.6503, "Tokyo"),
}


def demo_ucid_creation(city: str, lat: float, lon: float) -> str:
    """Demonstrate UCID creation.

    Args:
        city: City UN/LOCODE.
        lat: Latitude.
        lon: Longitude.

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
        timestamp="2026W02T14",
        context="15MIN",
        grade="A",
    )

    print("\nInput:")
    print(f"  City: {city}")
    print(f"  Coordinates: ({lat}, {lon})")
    print("\nGenerated UCID:")
    print(f"  {ucid}")

    return str(ucid)


def demo_ucid_parsing(ucid_string: str) -> None:
    """Demonstrate UCID parsing.

    Args:
        ucid_string: UCID string to parse.
    """
    print("\n" + "=" * 60)
    print("2. UCID Parsing")
    print("=" * 60)

    parsed = parse_ucid(ucid_string)

    print("\nParsed Components:")
    print(f"  City:       {parsed.city}")
    print(f"  H3 Cell:    {parsed.h3}")
    print(f"  Timestamp:  {parsed.timestamp}")
    print(f"  Context:    {parsed.context}")
    print(f"  Score:      {parsed.score}")
    print(f"  Grade:      {parsed.grade}")


def demo_spatial_ops(ucid_string: str) -> None:
    """Demonstrate spatial operations.

    Args:
        ucid_string: UCID string.
    """
    print("\n" + "=" * 60)
    print("3. Spatial Operations")
    print("=" * 60)

    parsed = parse_ucid(ucid_string)
    geojson = to_geojson(parsed.h3)

    print(f"\nH3 Cell: {parsed.h3}")
    print("\nGeoJSON Geometry:")
    print(f"  Type: {geojson['type']}")
    print(f"  Vertices: {len(geojson['coordinates'][0])}")


def demo_visualization() -> None:
    """Demonstrate visualization theming."""
    print("\n" + "=" * 60)
    print("4. Visualization Theme")
    print("=" * 60)

    theme = get_theme()

    print("\nTheme Configuration:")
    print(f"  Primary Color:   {theme.get('primary_color', 'N/A')}")
    print(f"  Secondary Color: {theme.get('secondary_color', 'N/A')}")


def demo_multi_context(city: str, lat: float, lon: float) -> None:
    """Demonstrate multi-context analysis.

    Args:
        city: City code.
        lat: Latitude.
        lon: Longitude.
    """
    print("\n" + "=" * 60)
    print("5. Multi-Context Analysis")
    print("=" * 60)

    contexts = ["15MIN", "TRANSIT", "CLIMATE", "WALK"]

    print(f"\n{'Context':<12} {'Score':>8}")
    print("-" * 20)

    for context in contexts:
        ucid = create_ucid(
            city=city,
            lat=lat,
            lon=lon,
            timestamp="2026W02T14",
            context=context,
        )
        parsed = parse_ucid(str(ucid))
        print(f"{context:<12} {parsed.score:>8}")


def print_header(city_name: str) -> None:
    """Print demo header."""
    print()
    print("╔" + "═" * 58 + "╗")
    print("║" + "UCID Comprehensive Demo".center(58) + "║")
    print("║" + f"Location: {city_name}".center(58) + "║")
    print("╚" + "═" * 58 + "╝")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="UCID comprehensive demo")
    parser.add_argument(
        "--city",
        "-c",
        type=str,
        default="IST",
        choices=list(CITY_COORDS.keys()),
        help="City code (default: IST)",
    )
    return parser.parse_args()


def main() -> int:
    """Run the comprehensive UCID demo.

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

    print("\n" + "=" * 60)
    print("Demo complete. See 'docs/instructions' for detailed guides.")
    print("=" * 60 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
