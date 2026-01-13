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
contexts including 15MIN, TRANSIT, CLIMATE, WALK, VITALITY, and EQUITY.

Example:
    >>> python multi_context.py
    Analyzing Taksim Square...
    15MIN: 85
    TRANSIT: 78
"""

from ucid import create_ucid, parse_ucid

# Available context types
CONTEXTS = ["15MIN", "TRANSIT", "CLIMATE", "WALK", "VITALITY", "EQUITY"]


def analyze_location(lat: float, lon: float, city: str = "IST") -> dict[str, dict]:
    """Analyze a location using all available contexts.

    Args:
        lat: Latitude.
        lon: Longitude.
        city: City UN/LOCODE.

    Returns:
        Dictionary with context results.
    """
    results = {}

    for context_name in CONTEXTS:
        ucid = create_ucid(
            city=city,
            lat=lat,
            lon=lon,
            timestamp="2026W02T14",
            context=context_name,
        )
        parsed = parse_ucid(str(ucid))
        results[context_name] = {
            "ucid": str(ucid),
            "score": parsed.score,
            "grade": parsed.grade,
        }

    return results


def main() -> None:
    """Run the multi-context analysis demonstration."""
    print("=" * 60)
    print("UCID Multi-Context Analysis Example")
    print("=" * 60)

    # Analysis location: Taksim Square, Istanbul
    lat, lon = 41.0370, 28.9850
    print(f"\nAnalyzing location: ({lat}, {lon})")
    print("Location: Taksim Square, Istanbul\n")

    # Analyze with all contexts
    results = analyze_location(lat, lon)

    # Display results
    print("-" * 60)
    print(f"{'Context':<12} {'Score':>8} {'Grade':>8}")
    print("-" * 60)

    for context, data in results.items():
        print(f"{context:<12} {data['score']:>8} {data['grade']:>8}")

    print("-" * 60)

    # Calculate average
    avg_score = sum(r["score"] for r in results.values()) / len(results)
    print(f"{'AVERAGE':<12} {avg_score:>8.1f}")

    # Summary
    print("\n" + "=" * 60)
    print("Multi-context analysis complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
