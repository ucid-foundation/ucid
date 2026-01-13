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

This script demonstrates batch processing of multiple locations to
generate UCIDs efficiently using pandas DataFrames.

Example:
    >>> python batch_processing.py
    Processing 100 locations...
    Mean score: 72.5
"""

import numpy as np
import pandas as pd

from ucid import create_ucid, parse_ucid


def generate_sample_locations(n: int = 100, seed: int = 42) -> pd.DataFrame:
    """Generate random sample locations within Istanbul.

    Args:
        n: Number of locations to generate.
        seed: Random seed for reproducibility.

    Returns:
        DataFrame with location_id, lat, lon columns.
    """
    np.random.seed(seed)
    return pd.DataFrame(
        {
            "location_id": range(n),
            "lat": np.random.uniform(40.8, 41.2, n),
            "lon": np.random.uniform(28.6, 29.4, n),
        }
    )


def process_batch(df: pd.DataFrame, context: str = "15MIN") -> pd.DataFrame:
    """Process a batch of locations and generate UCIDs.

    Args:
        df: DataFrame with lat, lon columns.
        context: UCID context type.

    Returns:
        DataFrame with UCID results.
    """
    results: list[dict] = []
    for _, row in df.iterrows():
        ucid = create_ucid(
            city="IST",
            lat=row["lat"],
            lon=row["lon"],
            timestamp="2026W02T14",
            context=context,
        )
        parsed = parse_ucid(str(ucid))
        results.append(
            {
                "location_id": row["location_id"],
                "ucid": str(ucid),
                "score": parsed.score,
                "grade": parsed.grade,
            }
        )
    return pd.DataFrame(results)


def main() -> None:
    """Run the batch processing demonstration."""
    print("=" * 60)
    print("UCID Batch Processing Example")
    print("=" * 60)

    # Generate sample locations
    print("\n1. Generating 100 sample locations...")
    locations = generate_sample_locations(100)
    print(f"   Generated {len(locations)} locations")

    # Process batch
    print("\n2. Processing batch...")
    results = process_batch(locations)
    print(f"   Processed {len(results)} UCIDs")

    # Show statistics
    print("\n3. Score Statistics:")
    print(f"   Mean:   {results['score'].mean():.1f}")
    print(f"   Median: {results['score'].median():.1f}")
    print(f"   Min:    {results['score'].min()}")
    print(f"   Max:    {results['score'].max()}")

    # Grade distribution
    print("\n4. Grade Distribution:")
    for grade, count in results["grade"].value_counts().sort_index().items():
        print(f"   Grade {grade}: {count}")

    # Show sample results
    print("\n5. Sample Results:")
    print(results.head(5).to_string(index=False))

    print("\n" + "=" * 60)
    print("Batch processing complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
