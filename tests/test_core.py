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

"""Tests for UCID core module."""

import pytest

from ucid import __version__
from ucid.core.errors import UCIDParseError
from ucid.core.models import City, UCID
from ucid.core.parser import create_ucid, parse_ucid
from ucid.core.registry import CityRegistry


class TestVersion:
    """Tests for version information."""

    def test_version_format(self) -> None:
        """Version should be a valid semver string."""
        parts = __version__.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_version_value(self) -> None:
        """Version should be 1.0.0."""
        assert __version__ == "1.0.0"


class TestCity:
    """Tests for City model."""

    def test_valid_city(self) -> None:
        """Valid city should be created successfully."""
        city = City(
            code="IST",
            full_name="Istanbul",
            country="TR",
            timezone="Europe/Istanbul",
        )
        assert city.code == "IST"
        assert city.full_name == "Istanbul"

    def test_invalid_timezone(self) -> None:
        """Invalid timezone should raise ValueError."""
        with pytest.raises(ValueError):
            City(
                code="TST",
                full_name="Test",
                country="XX",
                timezone="Invalid/Timezone",
            )


class TestCityRegistry:
    """Tests for CityRegistry."""

    def test_singleton(self) -> None:
        """Registry should be a singleton."""
        r1 = CityRegistry()
        r2 = CityRegistry()
        assert r1 is r2

    def test_default_cities_loaded(self) -> None:
        """Default cities should be pre-loaded."""
        registry = CityRegistry()
        assert registry.exists("IST")
        assert registry.exists("NYC")
        assert registry.exists("HEL")

    def test_get_city(self) -> None:
        """Getting a city should return correct data."""
        registry = CityRegistry()
        city = registry.get("IST")
        assert city.full_name == "Istanbul"
        assert city.country == "TR"


class TestParser:
    """Tests for UCID parser."""

    def test_create_ucid(self) -> None:
        """Creating a UCID should produce valid object."""
        ucid = create_ucid(
            city="IST",
            lat=41.015,
            lon=28.979,
            timestamp="2026W01T12",
            context="15MIN",
            grade="A",
            confidence=0.95,
        )
        assert ucid.city == "IST"
        assert ucid.lat == 41.015
        assert ucid.context == "15MIN"

    def test_ucid_string_format(self) -> None:
        """UCID string should follow canonical format."""
        ucid = create_ucid(
            city="IST",
            lat=41.015,
            lon=28.979,
            timestamp="2026W01T12",
            context="15MIN",
        )
        s = str(ucid)
        assert s.startswith("UCID-V1:")
        assert ":IST:" in s

    def test_parse_invalid_prefix(self) -> None:
        """Invalid prefix should raise error."""
        with pytest.raises(UCIDParseError):
            parse_ucid("INVALID:IST:+41.015:...")
