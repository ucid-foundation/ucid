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

"""Fuzz target for UCID validator functionality.

This module provides fuzzing coverage for the UCID validation
functionality to identify potential issues when validating
malformed or edge-case inputs.

The validator ensures UCID strings conform to the specification.
Fuzzing helps identify edge cases where validation might fail
unexpectedly or accept invalid inputs.

Fuzzing Metrics:
    - Target functions: ucid.validate_ucid(), ucid.is_valid_ucid()
    - Coverage goal: 80%+
    - Mutation strategies: Invalid components, boundary values

Example:
    Run locally with atheris:

    >>> python fuzz_validator.py -max_total_time=300

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


def test_validate_random_strings(data: bytes) -> None:
    """Fuzz test validate_ucid with random strings.

    Args:
        data: Random bytes from the fuzzer engine.

    Expected Behavior:
        - is_valid_ucid: Always returns bool, never crashes
        - validate_ucid: Raises UCIDValidationError for invalid inputs
    """
    from ucid.core.errors import UCIDError
    from ucid.core.validator import is_valid_ucid, validate_ucid

    fdp = atheris.FuzzedDataProvider(data)

    test_string = fdp.ConsumeUnicodeNoSurrogates(200)

    try:
        # Test boolean validation - must always return bool
        result = is_valid_ucid(test_string)
        assert isinstance(result, bool)

        # Test exception-raising validation
        validate_ucid(test_string)
    except UCIDError:
        # Expected for invalid inputs
        pass
    except (ValueError, TypeError):
        # Acceptable for malformed inputs
        pass


def test_validate_components(data: bytes) -> None:
    """Fuzz test validation of individual UCID components.

    Tests validation of:
    - City codes (3-letter codes)
    - Coordinates (latitude: -90 to 90, longitude: -180 to 180)
    - Timestamps (ISO week format)
    - Context types (15MIN, TRANSIT, WALK, NONE)
    - H3 indices (15-character hex strings)
    - Grades (A, B, C, D, F)
    - Scores (0.00 to 1.00)

    Args:
        data: Random bytes from the fuzzer engine.
    """
    from ucid.core.errors import UCIDError
    from ucid.core.validator import validate_ucid

    fdp = atheris.FuzzedDataProvider(data)

    # Generate UCID with random but structured components
    city = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 10))
    lat = fdp.ConsumeFloat()
    lon = fdp.ConsumeFloat()
    resolution = fdp.ConsumeIntInRange(-10, 20)
    h3_index = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 20))
    timestamp = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 15))
    context = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 10))
    grade = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 3))
    score = fdp.ConsumeFloat()

    test_string = (
        f"UCID-V1:{city}:{lat}:{lon}:{resolution}:"
        f"{h3_index}:{timestamp}:{context}:{grade}:{score}"
    )

    try:
        validate_ucid(test_string)
    except UCIDError:
        pass
    except (ValueError, TypeError):
        pass


def test_validate_boundary_values(data: bytes) -> None:
    """Fuzz test validation with boundary values.

    Tests extreme values for each component:
    - Coordinates at poles and antimeridian
    - Maximum/minimum resolution values
    - Edge case timestamps

    Args:
        data: Random bytes from the fuzzer engine.
    """
    from ucid.core.errors import UCIDError
    from ucid.core.validator import validate_ucid

    fdp = atheris.FuzzedDataProvider(data)

    boundary_cases = [
        # Pole coordinates
        f"UCID-V1:IST:90.0:180.0:9:891f2ed6df7ffff:2026W01T00:15MIN:A:1.00",
        f"UCID-V1:IST:-90.0:-180.0:9:891f2ed6df7ffff:2026W01T00:15MIN:F:0.00",
        # Invalid coordinates
        f"UCID-V1:IST:{fdp.ConsumeFloat()}:{fdp.ConsumeFloat()}:9:test:2026W01T00:15MIN:C:0.50",
        # Random structured
        f"UCID-V1:{fdp.ConsumeString(3)}:41.0:29.0:{fdp.ConsumeIntInRange(0, 15)}:"
        f"{fdp.ConsumeString(15)}:{fdp.ConsumeString(10)}:{fdp.ConsumeString(6)}:"
        f"{fdp.ConsumeString(1)}:{fdp.ConsumeFloat()}",
    ]

    for test_string in boundary_cases:
        try:
            validate_ucid(test_string)
        except UCIDError:
            pass
        except (ValueError, TypeError):
            pass


def test_one_input(data: bytes) -> None:
    """Main fuzz target entry point.

    This function is called by the fuzzer for each generated input.
    It runs all validator fuzzing test cases.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    test_validate_random_strings(data)
    test_validate_components(data)
    test_validate_boundary_values(data)


def main(argv: Sequence[str] | None = None) -> None:
    """Main entry point for the validator fuzzer.

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
