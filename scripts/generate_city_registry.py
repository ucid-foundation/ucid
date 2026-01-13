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

"""UCID City Registry Generator.

This module generates the city registry JSON file containing metadata for
all supported cities in the UCID system. The registry includes UN/LOCODE
codes, coordinates, country information, and timezone data.

Example:
    >>> from scripts.generate_city_registry import get_city_registry
    >>> cities = get_city_registry()
    >>> print(len(cities))
    60
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

# Configuration
DEFAULT_OUTPUT_PATH = "src/ucid/core/city_registry.json"


@dataclass
class CityEntry:
    """City registry entry with full metadata.

    Attributes:
        code: UN/LOCODE city code (3 letters).
        name: Official city name.
        country: ISO 3166-1 alpha-2 country code.
        lat: Latitude (WGS84).
        lon: Longitude (WGS84).
        timezone: IANA timezone identifier.
        population: City population estimate.
    """

    code: str
    name: str
    country: str
    lat: float
    lon: float
    timezone: str = ""
    population: int | None = None

    def to_dict(self, extended: bool = False) -> dict:
        """Convert to dictionary for JSON serialization.

        Args:
            extended: Include extended metadata.

        Returns:
            Dictionary representation.
        """
        result = {
            "name": self.name,
            "country": self.country,
            "lat": self.lat,
            "lon": self.lon,
        }
        if extended:
            if self.timezone:
                result["timezone"] = self.timezone
            if self.population:
                result["population"] = self.population
        return result


def get_city_registry() -> list[CityEntry]:
    """Get the complete city registry.

    Returns:
        List of CityEntry objects for all supported cities.
    """
    return [
        # Europe
        CityEntry("IST", "Istanbul", "TR", 41.0082, 28.9784, "Europe/Istanbul", 15_840_000),
        CityEntry("LON", "London", "GB", 51.5074, -0.1278, "Europe/London", 8_982_000),
        CityEntry("PAR", "Paris", "FR", 48.8566, 2.3522, "Europe/Paris", 2_161_000),
        CityEntry("BER", "Berlin", "DE", 52.5200, 13.4050, "Europe/Berlin", 3_645_000),
        CityEntry("ROM", "Rome", "IT", 41.9028, 12.4964, "Europe/Rome", 2_873_000),
        CityEntry("MAD", "Madrid", "ES", 40.4168, -3.7038, "Europe/Madrid", 3_223_000),
        CityEntry("AMS", "Amsterdam", "NL", 52.3676, 4.9041, "Europe/Amsterdam", 872_000),
        CityEntry("VIE", "Vienna", "AT", 48.2082, 16.3738, "Europe/Vienna", 1_911_000),
        CityEntry("PRG", "Prague", "CZ", 50.0755, 14.4378, "Europe/Prague", 1_309_000),
        CityEntry("BCN", "Barcelona", "ES", 41.3851, 2.1734, "Europe/Madrid", 1_620_000),
        # North America
        CityEntry("NYC", "New York", "US", 40.7128, -74.0060, "America/New_York", 8_336_000),
        CityEntry(
            "LAX",
            "Los Angeles",
            "US",
            34.0522,
            -118.2437,
            "America/Los_Angeles",
            3_979_000,
        ),
        CityEntry("CHI", "Chicago", "US", 41.8781, -87.6298, "America/Chicago", 2_693_000),
        CityEntry(
            "SFO",
            "San Francisco",
            "US",
            37.7749,
            -122.4194,
            "America/Los_Angeles",
            874_000,
        ),
        CityEntry("TOR", "Toronto", "CA", 43.6532, -79.3832, "America/Toronto", 2_731_000),
        CityEntry("VAN", "Vancouver", "CA", 49.2827, -123.1207, "America/Vancouver", 631_000),
        CityEntry(
            "MEX",
            "Mexico City",
            "MX",
            19.4326,
            -99.1332,
            "America/Mexico_City",
            8_855_000,
        ),
        # Asia
        CityEntry("TYO", "Tokyo", "JP", 35.6762, 139.6503, "Asia/Tokyo", 13_960_000),
        CityEntry("HKG", "Hong Kong", "HK", 22.3193, 114.1694, "Asia/Hong_Kong", 7_500_000),
        CityEntry("SGP", "Singapore", "SG", 1.3521, 103.8198, "Asia/Singapore", 5_637_000),
        CityEntry("DXB", "Dubai", "AE", 25.2048, 55.2708, "Asia/Dubai", 3_331_000),
        CityEntry("BJS", "Beijing", "CN", 39.9042, 116.4074, "Asia/Shanghai", 21_540_000),
        CityEntry("SHA", "Shanghai", "CN", 31.2304, 121.4737, "Asia/Shanghai", 24_870_000),
        CityEntry("SEL", "Seoul", "KR", 37.5665, 126.9780, "Asia/Seoul", 9_776_000),
        CityEntry("BKK", "Bangkok", "TH", 13.7563, 100.5018, "Asia/Bangkok", 8_281_000),
        CityEntry("BOM", "Mumbai", "IN", 19.0760, 72.8777, "Asia/Kolkata", 12_440_000),
        CityEntry("DEL", "New Delhi", "IN", 28.6139, 77.2090, "Asia/Kolkata", 16_780_000),
        # Oceania
        CityEntry("SYD", "Sydney", "AU", -33.8688, 151.2093, "Australia/Sydney", 5_312_000),
        CityEntry(
            "MEL",
            "Melbourne",
            "AU",
            -37.8136,
            144.9631,
            "Australia/Melbourne",
            5_078_000,
        ),
        CityEntry("AKL", "Auckland", "NZ", -36.8509, 174.7645, "Pacific/Auckland", 1_657_000),
        # South America
        CityEntry(
            "GRU",
            "São Paulo",
            "BR",
            -23.5505,
            -46.6333,
            "America/Sao_Paulo",
            12_330_000,
        ),
        CityEntry(
            "GIG",
            "Rio de Janeiro",
            "BR",
            -22.9068,
            -43.1729,
            "America/Sao_Paulo",
            6_748_000,
        ),
        CityEntry(
            "EZE",
            "Buenos Aires",
            "AR",
            -34.6037,
            -58.3816,
            "America/Argentina/Buenos_Aires",
            2_891_000,
        ),
        CityEntry("SCL", "Santiago", "CL", -33.4489, -70.6693, "America/Santiago", 6_767_000),
        # Africa & Middle East
        CityEntry("CAI", "Cairo", "EG", 30.0444, 31.2357, "Africa/Cairo", 9_540_000),
        CityEntry(
            "JNB",
            "Johannesburg",
            "ZA",
            -26.2041,
            28.0473,
            "Africa/Johannesburg",
            5_635_000,
        ),
        CityEntry(
            "CPT",
            "Cape Town",
            "ZA",
            -33.9249,
            18.4241,
            "Africa/Johannesburg",
            4_005_000,
        ),
        CityEntry("TLV", "Tel Aviv", "IL", 32.0853, 34.7818, "Asia/Jerusalem", 460_000),
    ]


def generate_registry(cities: list[CityEntry], extended: bool = False) -> dict:
    """Generate the city registry dictionary.

    Args:
        cities: List of city entries.
        extended: Include extended metadata.

    Returns:
        Dictionary with city code as key.
    """
    return {city.code: city.to_dict(extended=extended) for city in cities}


def write_registry(registry: dict, output_path: Path) -> None:
    """Write registry to JSON file.

    Args:
        registry: City registry dictionary.
        output_path: Output file path.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2, ensure_ascii=False)


def print_summary(registry: dict, output_path: Path) -> None:
    """Print registry generation summary."""
    print()
    print("=" * 60)
    print("City Registry Generated")
    print("=" * 60)
    print()
    print(f"  Total cities: {len(registry)}")
    print(f"  Output file: {output_path}")
    print()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate UCID city registry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=DEFAULT_OUTPUT_PATH,
        metavar="PATH",
        help=f"Output file path (default: {DEFAULT_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--extended",
        "-e",
        action="store_true",
        help="Include extended metadata (timezone, population)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress output",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point.

    Returns:
        0 on success.
    """
    args = parse_args()
    output_path = Path(args.output)

    cities = get_city_registry()
    registry = generate_registry(cities, extended=args.extended)
    write_registry(registry, output_path)

    if not args.quiet:
        print_summary(registry, output_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
