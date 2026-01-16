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

"""Fuzz target for UCID creator functionality.

This module provides fuzzing coverage for the UCID creation
functionality to identify potential issues when creating UCIDs
with invalid or edge-case inputs.

The creator function is the primary entry point for generating
new UCIDs. Fuzzing helps ensure it handles all input combinations
gracefully.

Fuzzing Metrics:
    - Target function: ucid.create_ucid()
    - Coverage goal: 80%+
    - Mutation strategies: Random coordinates, invalid cities, edge cases

Example:
    Run locally with atheris:

    >>> python fuzz_creator.py -max_total_time=300

Reference:
    https://google.github.io/clusterfuzzlite/
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

try:
    import atheris
except ImportError:
    raise ImportError(
        "atheris is required for fuzzing. Install with: pip install atheris"
    )

if TYPE_CHECKING:
    from collections.abc import Sequence


# Valid city codes for testing
VALID_CITY_CODES = ["IST", "BER", "LON", "NEW", "PAR", "SYD", "TOK"]

# Valid context types
VALID_CONTEXTS = ["15MIN", "TRANSIT", "WALK", "NONE"]


def test_create_with_valid_cities(data: bytes) -> None:
    """Fuzz test create_ucid with valid city codes.

    Tests UCID creation with known valid city codes but random
    coordinate values to identify boundary issues.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    from ucid import create_ucid
    from ucid.core.errors import UCIDError

    fdp = atheris.FuzzedDataProvider(data)

    city = fdp.PickValueInList(VALID_CITY_CODES)
    lat = fdp.ConsumeFloatInRange(-90.0, 90.0)
    lon = fdp.ConsumeFloatInRange(-180.0, 180.0)
    context = fdp.PickValueInList(VALID_CONTEXTS)
    h3_res = fdp.ConsumeIntInRange(7, 11)

    try:
        result = create_ucid(
            city=city,
            lat=lat,
            lon=lon,
            context=context,
            h3_res=h3_res,
        )
        # Verify result integrity
        assert result is not None
        assert result.city == city
        assert result.context == context
    except UCIDError:
        pass
    except (ValueError, TypeError):
        pass


def test_create_with_random_inputs(data: bytes) -> None:
    """Fuzz test create_ucid with completely random inputs.

    Tests UCID creation with random values for all parameters
    to identify unexpected crashes or behaviors.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    from ucid import create_ucid
    from ucid.core.errors import UCIDError

    fdp = atheris.FuzzedDataProvider(data)

    # Random city code (may be invalid)
    city = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 10))

    # Random coordinates (may be out of range)
    lat = fdp.ConsumeFloat()
    lon = fdp.ConsumeFloat()

    # Random context (may be invalid)
    context = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 10))

    # Random resolution (may be out of range)
    h3_res = fdp.ConsumeIntInRange(-10, 20)

    try:
        create_ucid(
            city=city,
            lat=lat,
            lon=lon,
            context=context,
            h3_res=h3_res,
        )
    except UCIDError:
        # Expected for invalid inputs
        pass
    except (ValueError, TypeError):
        # Acceptable for malformed inputs
        pass


def test_create_edge_cases(data: bytes) -> None:
    """Fuzz test create_ucid with edge case inputs.

    Tests:
    - Extreme coordinate values (poles, antimeridian)
    - Empty strings
    - Unicode city codes
    - Boundary H3 resolutions

    Args:
        data: Random bytes from the fuzzer engine.
    """
    from ucid import create_ucid
    from ucid.core.errors import UCIDError

    fdp = atheris.FuzzedDataProvider(data)

    edge_cases = [
        # Poles
        {"city": "IST", "lat": 90.0, "lon": 0.0, "context": "NONE"},
        {"city": "IST", "lat": -90.0, "lon": 0.0, "context": "NONE"},
        # Antimeridian
        {"city": "IST", "lat": 0.0, "lon": 180.0, "context": "NONE"},
        {"city": "IST", "lat": 0.0, "lon": -180.0, "context": "NONE"},
        # Origin
        {"city": "IST", "lat": 0.0, "lon": 0.0, "context": "NONE"},
        # Random with unicode
        {
            "city": fdp.ConsumeUnicodeNoSurrogates(3),
            "lat": fdp.ConsumeFloatInRange(-90.0, 90.0),
            "lon": fdp.ConsumeFloatInRange(-180.0, 180.0),
            "context": "NONE",
        },
    ]

    for params in edge_cases:
        try:
            create_ucid(**params)
        except UCIDError:
            pass
        except (ValueError, TypeError):
            pass


def test_one_input(data: bytes) -> None:
    """Main fuzz target entry point.

    This function is called by the fuzzer for each generated input.
    It runs all creator fuzzing test cases.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    test_create_with_valid_cities(data)
    test_create_with_random_inputs(data)
    test_create_edge_cases(data)


def main(argv: Sequence[str] | None = None) -> None:
    """Main entry point for the creator fuzzer.

    Args:
        argv: Command-line arguments. Defaults to sys.argv.
    """
    if argv is None:
        argv = sys.argv

    atheris.Setup(
        argv,
        test_one_input,
        enable_python_coverage=True,
    )
    atheris.Fuzz()


if __name__ == "__main__":
    main()
