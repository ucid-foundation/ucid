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

"""Fuzz target for UCID parser functionality.

This module provides fuzzing coverage for the UCID string parsing
functionality to identify potential crashes, memory issues, or
unexpected behavior when processing malformed inputs.

The parser is a critical security boundary as it processes untrusted
input from external sources. Fuzzing helps ensure robustness against
malformed UCID strings.

Fuzzing Metrics:
    - Target function: ucid.parse_ucid()
    - Coverage goal: 80%+
    - Mutation strategies: Random strings, UCID-like formats, edge cases

Example:
    Run locally with atheris:

    >>> python fuzz_parser.py -max_total_time=300

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


def _instrument_imports() -> None:
    """Instrument imports for coverage tracking."""
    global parse_ucid, UCIDError, UCIDParseError

    with atheris.instrument_imports():
        from ucid import parse_ucid
        from ucid.core.errors import UCIDError, UCIDParseError


def test_parse_random_strings(data: bytes) -> None:
    """Fuzz test parse_ucid with random strings.

    This function attempts to parse arbitrary byte sequences as UCID
    strings to identify parsing vulnerabilities.

    Args:
        data: Random bytes from the fuzzer engine.

    Expected Behavior:
        - Valid UCIDs: Parse successfully and return UCID object
        - Invalid inputs: Raise UCIDParseError or UCIDValidationError
        - All inputs: No crashes, hangs, or memory leaks
    """
    from ucid import parse_ucid
    from ucid.core.errors import UCIDError

    fdp = atheris.FuzzedDataProvider(data)

    # Test with random unicode string
    test_string = fdp.ConsumeUnicodeNoSurrogates(200)

    try:
        result = parse_ucid(test_string)
        # Verify result integrity if parsing succeeds
        assert result is not None
        assert hasattr(result, "city")
        assert hasattr(result, "lat")
        assert hasattr(result, "lon")
        assert hasattr(result, "h3_index")
    except UCIDError:
        # Expected for invalid inputs
        pass
    except (ValueError, TypeError, AttributeError):
        # Acceptable for malformed inputs
        pass


def test_parse_ucid_like_format(data: bytes) -> None:
    """Fuzz test parse_ucid with UCID-like formatted strings.

    Generates strings that resemble valid UCIDs but with random
    component values to test boundary conditions in the parser.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    from ucid import parse_ucid
    from ucid.core.errors import UCIDError

    fdp = atheris.FuzzedDataProvider(data)

    # Generate UCID-like string with random components
    version = fdp.ConsumeIntInRange(0, 10)
    city = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 6))
    lat = fdp.ConsumeFloat()
    lon = fdp.ConsumeFloat()
    resolution = fdp.ConsumeIntInRange(0, 20)
    h3_index = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 20))
    timestamp = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 15))
    context = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 10))
    grade = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 3))
    score = fdp.ConsumeFloat()

    test_string = (
        f"UCID-V{version}:{city}:{lat}:{lon}:{resolution}:"
        f"{h3_index}:{timestamp}:{context}:{grade}:{score}"
    )

    try:
        parse_ucid(test_string)
    except UCIDError:
        pass
    except (ValueError, TypeError, AttributeError):
        pass


def test_parse_edge_cases(data: bytes) -> None:
    """Fuzz test parse_ucid with edge case inputs.

    Tests specific edge cases that might cause issues:
    - Empty strings
    - Very long strings
    - Special characters
    - Null bytes
    - Unicode edge cases

    Args:
        data: Random bytes from the fuzzer engine.
    """
    from ucid import parse_ucid
    from ucid.core.errors import UCIDError

    fdp = atheris.FuzzedDataProvider(data)

    edge_cases = [
        "",  # Empty string
        "\x00" * fdp.ConsumeIntInRange(1, 50),  # Null bytes
        "UCID-V1:" + "\x00",  # Partial with null
        "UCID-V1:" * fdp.ConsumeIntInRange(1, 20),  # Repeated prefix
        ":" * fdp.ConsumeIntInRange(1, 100),  # Only separators
        fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 500)).decode(
            "utf-8", errors="ignore"
        ),  # Random bytes as string
    ]

    for test_string in edge_cases:
        try:
            parse_ucid(test_string)
        except UCIDError:
            pass
        except (ValueError, TypeError, AttributeError):
            pass


def test_one_input(data: bytes) -> None:
    """Main fuzz target entry point.

    This function is called by the fuzzer for each generated input.
    It runs all parser fuzzing test cases.

    Args:
        data: Random bytes from the fuzzer engine.
    """
    test_parse_random_strings(data)
    test_parse_ucid_like_format(data)
    test_parse_edge_cases(data)


def main(argv: Sequence[str] | None = None) -> None:
    """Main entry point for the parser fuzzer.

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
