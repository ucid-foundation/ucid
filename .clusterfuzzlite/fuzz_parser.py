#!/usr/bin/env python3
# Copyright 2026 UCID Foundation
# Licensed under EUPL-1.2

"""Fuzz target for UCID parser."""

import sys

import atheris

with atheris.instrument_imports():
    from ucid import UCIDParseError, parse_ucid


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
