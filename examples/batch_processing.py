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

"""UCID Batch Processing Example.

This script demonstrates efficient batch processing of multiple locations
to generate UCIDs using pandas DataFrames. Optimized for processing thousands
of locations with high throughput.

Library Statistics:
    - Total Cities: 405
    - Countries: 23
    - CREATE Performance: 127,575 ops/sec
    - Batch Throughput: 10,000+ locations/sec

Supported Contexts:
    - 15MIN: 15-minute city accessibility scoring
    - TRANSIT: Public transit accessibility
    - WALK: Walkability index
    - NONE: No context scoring

Performance Tips:
    - Process in batches of 1,000-10,000 for optimal memory usage
    - Use multiprocessing for datasets > 100,000 locations
    - Pre-filter invalid coordinates before processing
    - Cache results for repeated lookups

Example:
    >>> python batch_processing.py
    Processing 1000 locations...
    Mean score: 72.5
    Rate: 8,500 locations/sec

Version: 1.0.5
Last Updated: 2026-01-15
"""

from __future__ import annotations

import time
from collections import Counter

import numpy as np
import pandas as pd

from ucid import create_ucid, parse_ucid


# Sample cities for batch processing demo
CITIES: list[dict] = [
    {"code": "IST", "lat": 41.0082, "lon": 28.9784, "name": "Istanbul"},
    {"code": "BER", "lat": 52.5200, "lon": 13.4050, "name": "Berlin"},
    {"code": "AMS", "lat": 52.3702, "lon": 4.8952, "name": "Amsterdam"},
    {"code": "VIE", "lat": 48.2082, "lon": 16.3738, "name": "Vienna"},
    {"code": "MUN", "lat": 48.1351, "lon": 11.5820, "name": "Munich"},
]


def generate_sample_locations(
    n: int = 1000,
    seed: int = 42,
) -> pd.DataFrame:
    """Generate random sample locations across multiple cities.

    Creates a DataFrame with random locations distributed across
    the 5 sample cities, simulating real-world batch processing.

    Args:
        n: Number of locations to generate.
        seed: Random seed for reproducibility.

    Returns:
        DataFrame with columns: location_id, city, lat, lon.
    """
    np.random.seed(seed)

    # Distribute locations across cities
    locations_per_city = n // len(CITIES)
    remainder = n % len(CITIES)

    data = []
    loc_id = 0

    for i, city in enumerate(CITIES):
        count = locations_per_city + (1 if i < remainder else 0)
        for _ in range(count):
            # Add jitter around city center (+-0.05 degrees ~ 5km)
            lat = city["lat"] + np.random.uniform(-0.05, 0.05)
            lon = city["lon"] + np.random.uniform(-0.05, 0.05)
            data.append({
                "location_id": loc_id,
                "city_code": city["code"],
                "city_name": city["name"],
                "lat": lat,
                "lon": lon,
            })
            loc_id += 1

    return pd.DataFrame(data)


def process_batch(
    df: pd.DataFrame,
    context: str = "15MIN",
) -> pd.DataFrame:
    """Process a batch of locations and generate UCIDs.

    Iterates through the DataFrame and creates a UCID for each location.
    Returns a new DataFrame with UCID results.

    Args:
        df: DataFrame with city_code, lat, lon columns.
        context: UCID context type (15MIN, TRANSIT, WALK, NONE).

    Returns:
        DataFrame with UCID results including score and grade.
    """
    results: list[dict] = []

    for _, row in df.iterrows():
        ucid = create_ucid(
            city=row["city_code"],
            lat=row["lat"],
            lon=row["lon"],
            timestamp="2026W03T14",
            context=context,
        )
        parsed = parse_ucid(str(ucid))
        results.append({
            "location_id": row["location_id"],
            "city_code": row["city_code"],
            "city_name": row["city_name"],
            "ucid": str(ucid),
            "score": parsed.score,
            "grade": parsed.grade,
            "confidence": parsed.confidence,
        })

    return pd.DataFrame(results)


def print_statistics(df: pd.DataFrame) -> None:
    """Print comprehensive statistics for processed UCIDs.

    Args:
        df: DataFrame with UCID results.
    """
    print("\n3. Score Statistics:")
    print(f"   Mean:   {df['score'].mean():.1f}")
    print(f"   Median: {df['score'].median():.1f}")
    print(f"   Std:    {df['score'].std():.1f}")
    print(f"   Min:    {df['score'].min()}")
    print(f"   Max:    {df['score'].max()}")


def print_grade_distribution(df: pd.DataFrame) -> None:
    """Print grade distribution for processed UCIDs.

    Args:
        df: DataFrame with UCID results.
    """
    print("\n4. Grade Distribution:")
    grades = Counter(df["grade"])
    total = len(df)

    for grade in ["A", "B", "C", "D", "F"]:
        count = grades.get(grade, 0)
        pct = 100 * count / total
        bar = "#" * int(pct / 2)
        print(f"   {grade}: {count:4d} ({pct:5.1f}%) {bar}")


def print_city_breakdown(df: pd.DataFrame) -> None:
    """Print breakdown by city.

    Args:
        df: DataFrame with UCID results.
    """
    print("\n5. City Breakdown:")
    city_stats = df.groupby("city_name")["score"].agg(["mean", "count"])
    for city, row in city_stats.iterrows():
        print(f"   {city}: {row['count']:4.0f} locations, avg score {row['mean']:.1f}")


def main() -> None:
    """Run the batch processing demonstration.

    Demonstrates:
    1. Sample location generation
    2. Batch UCID processing
    3. Score statistics
    4. Grade distribution
    5. City breakdown
    """
    print("=" * 60)
    print("UCID Batch Processing Example")
    print("=" * 60)
    print("\nLibrary: UCID v1.0.5")
    print("Cities: 405 | Countries: 23")
    print("Expected throughput: 10,000+ locations/sec")

    # Generate sample locations
    n_locations = 1000
    print(f"\n1. Generating {n_locations} sample locations...")
    locations = generate_sample_locations(n_locations)
    print(f"   Generated {len(locations)} locations across {len(CITIES)} cities")

    # Process batch with timing
    print("\n2. Processing batch with 15MIN context...")
    start_time = time.time()
    results = process_batch(locations, context="15MIN")
    elapsed = time.time() - start_time
    rate = len(results) / elapsed
    print(f"   Processed {len(results)} UCIDs in {elapsed:.2f}s")
    print(f"   Rate: {rate:,.0f} locations/sec")

    # Show statistics
    print_statistics(results)
    print_grade_distribution(results)
    print_city_breakdown(results)

    # Show sample results
    print("\n6. Sample Results:")
    print(results[["city_name", "score", "grade"]].head(10).to_string(index=False))

    print("\n" + "=" * 60)
    print("Batch processing complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
