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

"""UCID Multi-Context Analysis Example.

This script demonstrates how to analyze a location using multiple urban
context algorithms. Each context provides different insights about urban
accessibility and quality of life.

Library Statistics:
    - Total Cities: 405
    - Countries: 23
    - CREATE Performance: 127,575 ops/sec

Available Contexts (Production):
    - 15MIN: 15-minute city accessibility - measures access to essential
             services (education, healthcare, food, recreation) within
             15 minutes by foot or bike.
    - TRANSIT: Transit accessibility - evaluates public transportation
               coverage based on stop density, route frequency, and
               service types.
    - WALK: Walkability - assesses pedestrian infrastructure including
            sidewalk coverage, intersection density, and traffic safety.
    - NONE: No context - returns only location-based UCID without scoring.

Grade Scale:
    - A: 0.80-1.00 (Excellent)
    - B: 0.60-0.80 (Good)
    - C: 0.40-0.60 (Moderate)
    - D: 0.20-0.40 (Limited)
    - F: 0.00-0.20 (Poor)

Example:
    >>> python multi_context.py
    Analyzing Taksim Square, Istanbul...
    15MIN: 85 (Grade A)
    TRANSIT: 78 (Grade B)

Version: 1.0.5
Last Updated: 2026-01-15
"""

from __future__ import annotations

from ucid import create_ucid, parse_ucid


# Production-ready context types
CONTEXTS: list[str] = ["15MIN", "TRANSIT", "WALK", "NONE"]

# Sample cities from the 405-city registry
SAMPLE_CITIES: list[dict] = [
    {"code": "IST", "name": "Taksim Square, Istanbul", "lat": 41.0370, "lon": 28.9850},
    {"code": "BER", "name": "Alexanderplatz, Berlin", "lat": 52.5219, "lon": 13.4132},
    {"code": "AMS", "name": "Centraal Station, Amsterdam", "lat": 52.3791, "lon": 4.9003},
]


def analyze_location(
    lat: float,
    lon: float,
    city: str = "IST",
) -> dict[str, dict]:
    """Analyze a location using all available production contexts.

    Creates UCIDs for each context type and returns a dictionary
    with scores, grades, and confidence levels.

    Args:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        city: City UN/LOCODE (3-letter code).

    Returns:
        Dictionary mapping context names to result dictionaries
        containing ucid, score, grade, and confidence.
    """
    results = {}

    for context_name in CONTEXTS:
        ucid = create_ucid(
            city=city,
            lat=lat,
            lon=lon,
            timestamp="2026W03T14",
            context=context_name,
        )
        parsed = parse_ucid(str(ucid))
        results[context_name] = {
            "ucid": str(ucid),
            "score": parsed.score,
            "grade": parsed.grade,
            "confidence": parsed.confidence,
        }

    return results


def print_results(results: dict[str, dict], location_name: str) -> None:
    """Print formatted analysis results.

    Args:
        results: Dictionary of context results.
        location_name: Name of the analyzed location.
    """
    print(f"\nLocation: {location_name}")
    print("-" * 50)
    print(f"{'Context':<12} {'Score':>8} {'Grade':>8} {'Confidence':>12}")
    print("-" * 50)

    for context, data in results.items():
        conf_pct = int(data["confidence"] * 100)
        print(f"{context:<12} {data['score']:>8} {data['grade']:>8} {conf_pct:>11}%")

    print("-" * 50)

    # Calculate averages (excluding NONE)
    scored_contexts = {k: v for k, v in results.items() if k != "NONE"}
    if scored_contexts:
        avg_score = sum(r["score"] for r in scored_contexts.values()) / len(scored_contexts)
        print(f"{'AVERAGE':<12} {avg_score:>8.1f}")


def main() -> None:
    """Run the multi-context analysis demonstration.

    Analyzes multiple locations from different cities using all
    production context types.
    """
    print("=" * 60)
    print("UCID Multi-Context Analysis Example")
    print("=" * 60)
    print("\nLibrary: UCID v1.0.5")
    print("Cities: 405 | Countries: 23")
    print(f"Available contexts: {', '.join(CONTEXTS)}")

    print("\n" + "=" * 60)
    print("Analyzing Multiple Cities")
    print("=" * 60)

    for city in SAMPLE_CITIES:
        results = analyze_location(
            lat=city["lat"],
            lon=city["lon"],
            city=city["code"],
        )
        print_results(results, city["name"])

    print("\n" + "=" * 60)
    print("Context Descriptions")
    print("=" * 60)
    print("""
    15MIN    - 15-Minute City: Access to essential services
               (education, healthcare, food, recreation) within
               15 minutes by foot or bike.

    TRANSIT  - Transit Accessibility: Public transportation
               coverage based on stop density and frequency.

    WALK     - Walkability: Pedestrian infrastructure quality
               including sidewalks and crossing safety.

    NONE     - No Context: Location-only UCID without scoring.
    """)

    print("\n" + "=" * 60)
    print("Multi-context analysis complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
