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

"""Comprehensive unit tests for UCID models."""

import pytest
from pydantic import ValidationError

from ucid.core.constants import VALID_GRADES
from ucid.core.models import UCID, City


class TestCityModel:
    """Tests for City model."""

    def test_city_creation_valid(self) -> None:
        """Test creating a valid City."""
        city = City(
            code="IST",
            full_name="Istanbul",
            country="TR",
            timezone="Europe/Istanbul",
        )
        assert city.code == "IST"
        assert city.full_name == "Istanbul"
        assert city.country == "TR"
        assert city.timezone == "Europe/Istanbul"

    def test_city_with_population(self) -> None:
        """Test City with population."""
        city = City(
            code="NYC",
            full_name="New York City",
            country="US",
            timezone="America/New_York",
            population=8_336_817,
        )
        assert city.population == 8_336_817

    def test_city_with_bbox(self) -> None:
        """Test City with bounding box."""
        city = City(
            code="LON",
            full_name="London",
            country="GB",
            timezone="Europe/London",
            bbox=(51.2867, -0.5103, 51.6918, 0.3340),
        )
        assert city.bbox == (51.2867, -0.5103, 51.6918, 0.3340)

    def test_city_invalid_code_length(self) -> None:
        """Test City with invalid code length."""
        with pytest.raises(ValidationError):
            City(
                code="ISTANBUL",
                full_name="Istanbul",
                country="TR",
                timezone="Europe/Istanbul",
            )

    def test_city_invalid_country_code(self) -> None:
        """Test City with invalid country code."""
        with pytest.raises(ValidationError):
            City(
                code="IST",
                full_name="Istanbul",
                country="TUR",  # Should be 2 characters
                timezone="Europe/Istanbul",
            )

    def test_city_invalid_timezone(self) -> None:
        """Test City with invalid timezone."""
        with pytest.raises(ValidationError):
            City(
                code="IST",
                full_name="Istanbul",
                country="TR",
                timezone="Invalid/Timezone",
            )

    def test_city_lowercase_code(self) -> None:
        """Test City with lowercase code (should fail pattern)."""
        with pytest.raises(ValidationError):
            City(
                code="ist",
                full_name="Istanbul",
                country="TR",
                timezone="Europe/Istanbul",
            )

    def test_city_frozen(self) -> None:
        """Test that City is frozen (immutable)."""
        city = City(
            code="BER",
            full_name="Berlin",
            country="DE",
            timezone="Europe/Berlin",
        )
        with pytest.raises(ValidationError):
            city.code = "MUN"


class TestUCIDModel:
    """Tests for UCID model."""

    def test_ucid_creation_valid(self) -> None:
        """Test creating a valid UCID."""
        ucid = UCID(
            version="V1",
            city="IST",
            lat=41.015,
            lon=28.979,
            h3_res=9,
            h3_index="891f2ed6df7ffff",
            timestamp="2026W03T14",
            context="15MIN",
            grade="A",
            confidence=0.95,
        )
        assert ucid.city == "IST"
        assert ucid.grade == "A"
        assert ucid.confidence == 0.95

    def test_ucid_lat3_property(self) -> None:
        """Test lat3 property formatting."""
        ucid = UCID(
            version="V1",
            city="IST",
            lat=41.0156789,
            lon=28.979,
            h3_res=9,
            h3_index="891f2ed6df7ffff",
            timestamp="2026W03T14",
            context="15MIN",
            grade="B",
            confidence=0.8,
        )
        assert ucid.lat3 == "+41.016"

    def test_ucid_lon3_property(self) -> None:
        """Test lon3 property formatting."""
        ucid = UCID(
            version="V1",
            city="NYC",
            lat=40.712,
            lon=-74.0060123,
            h3_res=9,
            h3_index="891f2ed6df7ffff",
            timestamp="2026W03T14",
            context="TRANSIT",
            grade="A",
            confidence=0.9,
        )
        assert ucid.lon3 == "-74.006"

    def test_ucid_conf2_property(self) -> None:
        """Test conf2 property formatting."""
        ucid = UCID(
            version="V1",
            city="IST",
            lat=41.015,
            lon=28.979,
            h3_res=9,
            h3_index="891f2ed6df7ffff",
            timestamp="2026W03T14",
            context="15MIN",
            grade="B",
            confidence=0.956789,
        )
        assert ucid.conf2 == "0.96"

    def test_ucid_flags_str_property(self) -> None:
        """Test flags_str property."""
        ucid = UCID(
            version="V1",
            city="IST",
            lat=41.015,
            lon=28.979,
            h3_res=9,
            h3_index="891f2ed6df7ffff",
            timestamp="2026W03T14",
            context="15MIN",
            grade="C",
            confidence=0.7,
            flags=["RUSH", "APPROX"],
        )
        # Flags are sorted
        assert "APPROX" in ucid.flags_str
        assert "RUSH" in ucid.flags_str

    def test_ucid_to_canonical_string(self) -> None:
        """Test to_canonical_string method."""
        ucid = UCID(
            version="V1",
            city="IST",
            lat=41.015,
            lon=28.979,
            h3_res=9,
            h3_index="891f2ed6df7ffff",
            timestamp="2026W03T14",
            context="15MIN",
            grade="A",
            confidence=0.95,
        )
        canonical = ucid.to_canonical_string()
        assert canonical.startswith("UCID-V1:")
        assert ":IST:" in canonical
        assert ":15MIN:" in canonical
        assert ":A:" in canonical

    def test_ucid_str_method(self) -> None:
        """Test __str__ method."""
        ucid = UCID(
            version="V1",
            city="LON",
            lat=51.507,
            lon=-0.128,
            h3_res=9,
            h3_index="891f2ed6df7ffff",
            timestamp="2026W05T10",
            context="15MIN",
            grade="B",
            confidence=0.8,
        )
        assert str(ucid) == ucid.to_canonical_string()

    def test_ucid_invalid_grade(self) -> None:
        """Test UCID with invalid grade."""
        with pytest.raises(ValidationError):
            UCID(
                version="V1",
                city="IST",
                lat=41.015,
                lon=28.979,
                h3_res=9,
                h3_index="891f2ed6df7ffff",
                timestamp="2026W03T14",
                context="15MIN",
                grade="X",  # Invalid grade
                confidence=0.95,
            )

    def test_ucid_all_valid_grades(self) -> None:
        """Test all valid grades."""
        for grade in VALID_GRADES:
            ucid = UCID(
                version="V1",
                city="IST",
                lat=41.015,
                lon=28.979,
                h3_res=9,
                h3_index="891f2ed6df7ffff",
                timestamp="2026W03T14",
                context="15MIN",
                grade=grade,
                confidence=0.5,
            )
            assert ucid.grade == grade

    def test_ucid_invalid_latitude(self) -> None:
        """Test UCID with invalid latitude."""
        with pytest.raises(ValidationError):
            UCID(
                version="V1",
                city="IST",
                lat=100.0,  # Invalid: > 90
                lon=28.979,
                h3_res=9,
                h3_index="891f2ed6df7ffff",
                timestamp="2026W03T14",
                context="15MIN",
                grade="A",
                confidence=0.95,
            )

    def test_ucid_invalid_longitude(self) -> None:
        """Test UCID with invalid longitude."""
        with pytest.raises(ValidationError):
            UCID(
                version="V1",
                city="IST",
                lat=41.015,
                lon=200.0,  # Invalid: > 180
                h3_res=9,
                h3_index="891f2ed6df7ffff",
                timestamp="2026W03T14",
                context="15MIN",
                grade="A",
                confidence=0.95,
            )

    def test_ucid_invalid_confidence(self) -> None:
        """Test UCID with invalid confidence."""
        with pytest.raises(ValidationError):
            UCID(
                version="V1",
                city="IST",
                lat=41.015,
                lon=28.979,
                h3_res=9,
                h3_index="891f2ed6df7ffff",
                timestamp="2026W03T14",
                context="15MIN",
                grade="A",
                confidence=1.5,  # Invalid: > 1.0
            )

    def test_ucid_invalid_h3_resolution(self) -> None:
        """Test UCID with invalid H3 resolution."""
        with pytest.raises(ValidationError):
            UCID(
                version="V1",
                city="IST",
                lat=41.015,
                lon=28.979,
                h3_res=20,  # Invalid: > 15
                h3_index="891f2ed6df7ffff",
                timestamp="2026W03T14",
                context="15MIN",
                grade="A",
                confidence=0.95,
            )

    def test_ucid_frozen(self) -> None:
        """Test that UCID is frozen (immutable)."""
        ucid = UCID(
            version="V1",
            city="IST",
            lat=41.015,
            lon=28.979,
            h3_res=9,
            h3_index="891f2ed6df7ffff",
            timestamp="2026W03T14",
            context="15MIN",
            grade="A",
            confidence=0.95,
        )
        with pytest.raises(ValidationError):
            ucid.grade = "B"
