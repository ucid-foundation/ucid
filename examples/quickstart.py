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

This script demonstrates the basic usage of the UCID library for urban
context analysis. It covers creating, parsing, and validating UCIDs.

Example:
    >>> python quickstart.py
    UCID Quickstart Example
    Created: UCID-V1:IST:+41.008:+28.978:...
"""

from ucid import create_ucid, parse_ucid
from ucid.core.validator import is_valid_ucid


def main() -> None:
    """Run the quickstart demonstration."""
    print("=" * 60)
    print("UCID Quickstart Example")
    print("=" * 60)

    # 1. Create a UCID for Istanbul
    print("\n1. Creating a UCID for Istanbul...")
    ucid = create_ucid(
        city="IST",
        lat=41.0082,
        lon=28.9784,
        timestamp="2026W02T14",
        context="15MIN",
    )
    print(f"   Created: {ucid}")

    # 2. Validate a UCID
    print("\n2. Validating UCIDs...")
    print(f"   Valid UCID: {is_valid_ucid(str(ucid))}")
    print(f"   Invalid string: {is_valid_ucid('not-a-ucid')}")

    # 3. Parse a UCID
    print("\n3. Parsing the UCID...")
    parsed = parse_ucid(str(ucid))
    print(f"   City: {parsed.city}")
    print(f"   H3 Index: {parsed.h3}")
    print(f"   Timestamp: {parsed.timestamp}")
    print(f"   Context: {parsed.context}")
    print(f"   Score: {parsed.score}")
    print(f"   Grade: {parsed.grade}")
    print(f"   Confidence: {int(parsed.confidence * 100)}%")

    # 4. Get coordinates from UCID
    print("\n4. Extracting coordinates...")
    lat, lon = parsed.to_coordinates()
    print(f"   Latitude: {lat:.6f}")
    print(f"   Longitude: {lon:.6f}")

    print("\n" + "=" * 60)
    print("Quickstart complete! See docs for more examples.")
    print("=" * 60)


if __name__ == "__main__":
    main()
