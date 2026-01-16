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

"""UCID Quickstart Example.

This script demonstrates the fundamental usage of the UCID library for urban
context analysis. It covers creating, parsing, and validating UCIDs across
the 405 registered cities in the UCID registry.

Library Statistics:
    - Total Cities: 405
    - Countries: 23
    - CREATE Performance: 127,575 ops/sec
    - PARSE Performance: 61,443 ops/sec
    - VALIDATE Performance: 17,334 ops/sec

Supported Contexts:
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

Example:
    >>> python quickstart.py
    UCID Quickstart Example
    Created: UCID-V1:IST:+41.008:+28.978:...

Version: 1.0.5
Last Updated: 2026-01-15
"""

from __future__ import annotations

from ucid import create_ucid, parse_ucid
from ucid.core.validator import is_valid_ucid


# Sample cities from the 405-city registry
SAMPLE_CITIES: dict[str, tuple[float, float, str]] = {
    "IST": (41.0082, 28.9784, "Istanbul, Turkey"),
    "BER": (52.5200, 13.4050, "Berlin, Germany"),
    "AMS": (52.3702, 4.8952, "Amsterdam, Netherlands"),
    "VIE": (48.2082, 16.3738, "Vienna, Austria"),
    "ZUR": (47.3769, 8.5417, "Zurich, Switzerland"),
}


def demo_create_ucid() -> str:
    """Demonstrate UCID creation for a location.

    Creates a UCID for Istanbul using the 15MIN context algorithm.
    The UCID encodes location, time, context type, and score.

    Returns:
        Generated UCID string.
    """
    print("\n1. Creating a UCID for Istanbul...")
    ucid = create_ucid(
        city="IST",
        lat=41.0082,
        lon=28.9784,
        timestamp="2026W03T14",
        context="15MIN",
    )
    print(f"   Created: {ucid}")
    return str(ucid)


def demo_validate_ucid(ucid_string: str) -> None:
    """Demonstrate UCID validation.

    Validates both a valid UCID and an invalid string to show
    the validation behavior.

    Args:
        ucid_string: A valid UCID string to validate.
    """
    print("\n2. Validating UCIDs...")
    print(f"   Valid UCID: {is_valid_ucid(ucid_string)}")
    print(f"   Invalid string: {is_valid_ucid('not-a-valid-ucid')}")


def demo_parse_ucid(ucid_string: str) -> None:
    """Demonstrate UCID parsing.

    Parses a UCID string and extracts all components including
    city, coordinates, H3 index, timestamp, context, and score.

    Args:
        ucid_string: UCID string to parse.
    """
    print("\n3. Parsing the UCID...")
    parsed = parse_ucid(ucid_string)
    print(f"   City: {parsed.city}")
    print(f"   H3 Index: {parsed.h3}")
    print(f"   Timestamp: {parsed.timestamp}")
    print(f"   Context: {parsed.context}")
    print(f"   Score: {parsed.score}")
    print(f"   Grade: {parsed.grade}")
    print(f"   Confidence: {int(parsed.confidence * 100)}%")


def demo_coordinates(ucid_string: str) -> None:
    """Demonstrate coordinate extraction from UCID.

    Extracts the geographic coordinates from a parsed UCID.

    Args:
        ucid_string: UCID string to parse.
    """
    print("\n4. Extracting coordinates...")
    parsed = parse_ucid(ucid_string)
    lat, lon = parsed.to_coordinates()
    print(f"   Latitude: {lat:.6f}")
    print(f"   Longitude: {lon:.6f}")


def demo_multiple_cities() -> None:
    """Demonstrate UCID creation for multiple cities.

    Shows that the library supports 405 cities across 23 countries
    by creating UCIDs for sample cities from different countries.
    """
    print("\n5. Creating UCIDs for multiple cities...")
    for city_code, (lat, lon, city_name) in SAMPLE_CITIES.items():
        ucid = create_ucid(
            city=city_code,
            lat=lat,
            lon=lon,
            timestamp="2026W03T14",
            context="15MIN",
        )
        parsed = parse_ucid(str(ucid))
        print(f"   {city_name}: Grade {parsed.grade} (Score: {parsed.score})")


def main() -> None:
    """Run the quickstart demonstration.

    Demonstrates all fundamental UCID operations in sequence:
    1. UCID creation
    2. UCID validation
    3. UCID parsing
    4. Coordinate extraction
    5. Multi-city support
    """
    print("=" * 60)
    print("UCID Quickstart Example")
    print("=" * 60)
    print("\nLibrary: UCID v1.0.5")
    print("Cities: 405 | Countries: 23")
    print("Performance: 127,575 CREATE ops/sec")

    # Run demos
    ucid_string = demo_create_ucid()
    demo_validate_ucid(ucid_string)
    demo_parse_ucid(ucid_string)
    demo_coordinates(ucid_string)
    demo_multiple_cities()

    print("\n" + "=" * 60)
    print("Quickstart complete! See docs for more examples.")
    print("Documentation: https://ucid.readthedocs.io")
    print("=" * 60)


if __name__ == "__main__":
    main()
