"""Unit tests for core parser."""

import pytest

from ucid.core.errors import UCIDParseError
from ucid.core.parser import parse_ucid


def test_parse_valid_ucid():
    valid = "UCID-V1:IST:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"
    ucid = parse_ucid(valid)
    assert ucid.city == "IST"
    assert ucid.grade == "A"


def test_parse_invalid_prefix():
    with pytest.raises(UCIDParseError):
        parse_ucid("INVALID:IST:...")
