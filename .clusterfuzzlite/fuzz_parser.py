#!/usr/bin/env python3
# Copyright 2026 UCID Foundation
# Licensed under EUPL-1.2

"""Fuzz target for UCID parser.

Note: We import ucid BEFORE atheris instrumentation to avoid SEGV
with pydantic/pydantic_core when using AddressSanitizer.
"""

import sys

# Import ucid FIRST, before any atheris instrumentation
# This avoids SEGV issues with pydantic+atheris+ASAN
from ucid import UCIDParseError, parse_ucid  # noqa: E402

import atheris  # noqa: E402


def test_one_input(data: bytes) -> None:
    """Fuzz the parse_ucid function with random bytes."""
    try:
        fdp = atheris.FuzzedDataProvider(data)
        input_str = fdp.ConsumeUnicodeNoSurrogates(100)
        parse_ucid(input_str)
    except (UCIDParseError, ValueError, TypeError, AttributeError):
        pass  # Expected exceptions


def main() -> None:
    """Run the fuzzer."""
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
