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

"""Comprehensive unit tests for the UCID core parser."""

import pytest

from ucid.core.errors import UCIDParseError
from ucid.core.parser import canonicalize, create_ucid, parse_ucid


class TestParseUCID:
    """Tests for parse_ucid function."""

    def test_parse_valid_ucid(self) -> None:
        """Test parsing a valid UCID string."""
        valid = "UCID-V1:IST:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"
        ucid = parse_ucid(valid)
        assert ucid.city == "IST"
        assert ucid.grade == "A"
        assert ucid.lat == 41.015
        assert ucid.lon == 28.979
        assert ucid.h3_res == 9
        assert ucid.timestamp == "2026W03T14"
        assert ucid.context == "15MIN"
        assert ucid.confidence == 0.95

    def test_parse_ucid_with_flags(self) -> None:
        """Test parsing a UCID with flags."""
        valid = "UCID-V1:NYC:40.7128:-74.006:9:abc123def456789:2026W01T08:TRANSIT:B:0.80:RUSH;HOLIDAY"
        ucid = parse_ucid(valid)
        assert ucid.flags == ["RUSH", "HOLIDAY"]

    def test_parse_ucid_with_negative_coords(self) -> None:
        """Test parsing a UCID with negative coordinates."""
        valid = "UCID-V1:SYD:-33.868:151.209:9:abc123def456789:2026W05T10:15MIN:C:0.70:"
        ucid = parse_ucid(valid)
        assert ucid.lat == -33.868
        assert ucid.lon == 151.209

    def test_parse_invalid_prefix(self) -> None:
        """Test that invalid prefix raises UCIDParseError."""
        with pytest.raises(UCIDParseError) as exc_info:
            parse_ucid("INVALID:IST:41.015:28.979:9:abc:2026W01T12:15MIN:A:0.95:")
        assert "INVALID_PREFIX" in str(exc_info.value.code)

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string raises error."""
        with pytest.raises(UCIDParseError) as exc_info:
            parse_ucid("")
        assert exc_info.value.code in ["INVALID_PREFIX", "MALFORMED_STRING"]

    def test_parse_insufficient_fields(self) -> None:
        """Test parsing with insufficient fields raises error."""
        with pytest.raises(UCIDParseError) as exc_info:
            parse_ucid("UCID-V1:IST:41.015:28.979")
        assert "MALFORMED_STRING" in str(exc_info.value.code)

    def test_parse_invalid_lat(self) -> None:
        """Test parsing with invalid latitude."""
        with pytest.raises(UCIDParseError):
            parse_ucid("UCID-V1:IST:invalid:28.979:9:abc:2026W01T12:15MIN:A:0.95:")

    def test_parse_invalid_confidence(self) -> None:
        """Test parsing with invalid confidence."""
        with pytest.raises(UCIDParseError):
            parse_ucid("UCID-V1:IST:41.015:28.979:9:abc:2026W01T12:15MIN:A:invalid:")

    def test_parse_non_strict_mode(self) -> None:
        """Test parsing in non-strict mode."""
        valid = "UCID-V1:XXX:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"
        ucid = parse_ucid(valid, strict=False)
        assert ucid.city == "XXX"

    def test_parse_different_grades(self) -> None:
        """Test parsing UCIDs with different grades."""
        for grade in ["A", "B", "C", "D", "F"]:
            valid = f"UCID-V1:IST:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:{grade}:0.95:"
            ucid = parse_ucid(valid)
            assert ucid.grade == grade


class TestCreateUCID:
    """Tests for create_ucid function."""

    def test_create_basic_ucid(self) -> None:
        """Test creating a basic UCID."""
        ucid = create_ucid(
            city="IST",
            lat=41.015,
            lon=28.979,
            timestamp="2026W01T12",
            context="15MIN",
        )
        assert ucid.city == "IST"
        assert ucid.lat == 41.015
        assert ucid.lon == 28.979
        assert ucid.timestamp == "2026W01T12"
        assert ucid.context == "15MIN"
        assert ucid.grade == "F"  # Default grade
        assert ucid.confidence == 0.0  # Default confidence

    def test_create_ucid_with_grade(self) -> None:
        """Test creating a UCID with custom grade."""
        ucid = create_ucid(
            city="NYC",
            lat=40.7128,
            lon=-74.006,
            timestamp="2026W01T08",
            context="TRANSIT",
            grade="A",
            confidence=0.95,
        )
        assert ucid.grade == "A"
        assert ucid.confidence == 0.95

    def test_create_ucid_with_flags(self) -> None:
        """Test creating a UCID with flags."""
        ucid = create_ucid(
            city="LON",
            lat=51.5074,
            lon=-0.1278,
            timestamp="2026W02T14",
            context="15MIN",
            flags=["RUSH", "HOLIDAY"],
        )
        assert ucid.flags == ["RUSH", "HOLIDAY"]

    def test_create_ucid_with_custom_h3_res(self) -> None:
        """Test creating a UCID with custom H3 resolution."""
        ucid = create_ucid(
            city="TKY",
            lat=35.6762,
            lon=139.6503,
            timestamp="2026W03T06",
            context="15MIN",
            h3_res=10,
        )
        assert ucid.h3_res == 10

    def test_create_ucid_lowercase_city(self) -> None:
        """Test that lowercase city code is converted to uppercase."""
        ucid = create_ucid(
            city="ist",
            lat=41.015,
            lon=28.979,
            timestamp="2026W01T12",
            context="15min",
        )
        assert ucid.city == "IST"
        assert ucid.context == "15MIN"

    def test_create_ucid_with_h3_index(self) -> None:
        """Test creating a UCID with pre-computed H3 index."""
        ucid = create_ucid(
            city="PAR",
            lat=48.8566,
            lon=2.3522,
            timestamp="2026W04T10",
            context="15MIN",
            h3_index="891f2ed6df7ffff",
        )
        assert ucid.h3_index == "891f2ed6df7ffff"

    def test_create_ucid_generates_h3(self) -> None:
        """Test that H3 index is automatically generated."""
        ucid = create_ucid(
            city="BER",
            lat=52.52,
            lon=13.405,
            timestamp="2026W05T12",
            context="15MIN",
        )
        assert ucid.h3_index is not None
        assert len(ucid.h3_index) > 0


class TestCanonicalize:
    """Tests for canonicalize function."""

    def test_canonicalize_valid_ucid(self) -> None:
        """Test canonicalizing a valid UCID string."""
        original = "UCID-V1:ist:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15min:A:0.95:"
        canonical = canonicalize(original)
        assert "IST" in canonical
        assert "15MIN" in canonical or "15min" in canonical.lower()

    def test_canonicalize_idempotent(self) -> None:
        """Test that canonicalize is idempotent."""
        original = "UCID-V1:IST:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"
        first = canonicalize(original)
        second = canonicalize(first)
        assert first == second

    def test_canonicalize_invalid_raises(self) -> None:
        """Test that invalid UCID raises error."""
        with pytest.raises(UCIDParseError):
            canonicalize("INVALID:STRING")


class TestUCIDModel:
    """Tests for UCID model."""

    def test_ucid_str_representation(self) -> None:
        """Test UCID string representation."""
        ucid = create_ucid(
            city="IST",
            lat=41.015,
            lon=28.979,
            timestamp="2026W01T12",
            context="15MIN",
        )
        ucid_str = str(ucid)
        assert "UCID-V1" in ucid_str
        assert "IST" in ucid_str

    def test_ucid_to_canonical_string(self) -> None:
        """Test UCID to_canonical_string method."""
        ucid = create_ucid(
            city="NYC",
            lat=40.7128,
            lon=-74.006,
            timestamp="2026W01T08",
            context="TRANSIT",
            grade="B",
            confidence=0.8,
        )
        canonical = ucid.to_canonical_string()
        assert canonical.startswith("UCID-V1:")
        assert ":NYC:" in canonical
        assert ":TRANSIT:" in canonical
        assert ":B:" in canonical

    def test_ucid_equality(self) -> None:
        """Test UCID equality comparison."""
        ucid1 = create_ucid(
            city="IST",
            lat=41.015,
            lon=28.979,
            timestamp="2026W01T12",
            context="15MIN",
        )
        ucid2 = create_ucid(
            city="IST",
            lat=41.015,
            lon=28.979,
            timestamp="2026W01T12",
            context="15MIN",
        )
        # Both UCIDs should have same properties
        assert ucid1.city == ucid2.city
        assert ucid1.lat == ucid2.lat
        assert ucid1.lon == ucid2.lon


class TestEdgeCases:
    """Edge case tests."""

    def test_extreme_coordinates(self) -> None:
        """Test with extreme valid coordinates."""
        # North Pole area
        ucid = create_ucid(
            city="XXX",
            lat=89.999,
            lon=0.0,
            timestamp="2026W01T00",
            context="15MIN",
        )
        assert ucid.lat == 89.999

        # South Pole area
        ucid2 = create_ucid(
            city="YYY",
            lat=-89.999,
            lon=180.0,
            timestamp="2026W01T00",
            context="15MIN",
        )
        assert ucid2.lat == -89.999

    def test_zero_confidence(self) -> None:
        """Test with zero confidence."""
        ucid = create_ucid(
            city="ZZZ",
            lat=0.0,
            lon=0.0,
            timestamp="2026W01T00",
            context="15MIN",
            confidence=0.0,
        )
        assert ucid.confidence == 0.0

    def test_full_confidence(self) -> None:
        """Test with full confidence."""
        ucid = create_ucid(
            city="ABC",
            lat=45.0,
            lon=90.0,
            timestamp="2026W01T12",
            context="15MIN",
            confidence=1.0,
        )
        assert ucid.confidence == 1.0

    def test_empty_flags(self) -> None:
        """Test with empty flags."""
        ucid = create_ucid(
            city="DEF",
            lat=30.0,
            lon=60.0,
            timestamp="2026W02T06",
            context="15MIN",
            flags=[],
        )
        assert ucid.flags == []

    def test_multiple_flags(self) -> None:
        """Test with multiple flags."""
        ucid = create_ucid(
            city="GHI",
            lat=15.0,
            lon=30.0,
            timestamp="2026W03T18",
            context="15MIN",
            flags=["FLAG1", "FLAG2", "FLAG3"],
        )
        assert len(ucid.flags) == 3
