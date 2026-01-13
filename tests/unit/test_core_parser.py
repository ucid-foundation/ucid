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

"""Unit tests for the UCID core parser."""

import pytest

from ucid.core.errors import UCIDParseError
from ucid.core.parser import parse_ucid


def test_parse_valid_ucid() -> None:
    """Test parsing a valid UCID string."""
    valid = "UCID-V1:IST:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"
    ucid = parse_ucid(valid)
    assert ucid.city == "IST"
    assert ucid.grade == "A"


def test_parse_invalid_prefix() -> None:
    """Test that invalid prefix raises UCIDParseError."""
    with pytest.raises(UCIDParseError):
        parse_ucid("INVALID:IST:...")
