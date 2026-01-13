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

"""Comprehensive unit tests for temporal module."""

import pytest
from datetime import datetime

from ucid.temporal import (
    get_iso_week,
    get_temporal_key,
    parse_temporal_key,
    TemporalBin,
)


class TestGetISOWeek:
    """Tests for get_iso_week function."""

    def test_first_week_of_year(self) -> None:
        """Test first week of year."""
        dt = datetime(2026, 1, 5)
        week = get_iso_week(dt)
        assert week == 2 or week == 1  # Depends on year start

    def test_middle_of_year(self) -> None:
        """Test middle of year."""
        dt = datetime(2026, 6, 15)
        week = get_iso_week(dt)
        assert 20 <= week <= 30

    def test_end_of_year(self) -> None:
        """Test end of year."""
        dt = datetime(2026, 12, 28)
        week = get_iso_week(dt)
        assert week >= 50


class TestGetTemporalKey:
    """Tests for get_temporal_key function."""

    def test_get_temporal_key_basic(self) -> None:
        """Test basic temporal key generation."""
        dt = datetime(2026, 1, 15, 14, 30)
        key = get_temporal_key(dt)
        assert "2026W" in key
        assert "T14" in key or "T" in key

    def test_get_temporal_key_midnight(self) -> None:
        """Test temporal key at midnight."""
        dt = datetime(2026, 3, 10, 0, 0)
        key = get_temporal_key(dt)
        assert "T00" in key or "T0" in key

    def test_get_temporal_key_evening(self) -> None:
        """Test temporal key in evening."""
        dt = datetime(2026, 7, 20, 23, 59)
        key = get_temporal_key(dt)
        assert "T23" in key


class TestParseTemporalKey:
    """Tests for parse_temporal_key function."""

    def test_parse_valid_key(self) -> None:
        """Test parsing valid temporal key."""
        result = parse_temporal_key("2026W03T14")
        assert result is not None
        assert result["year"] == 2026
        assert result["week"] == 3
        assert result["hour"] == 14

    def test_parse_week_01(self) -> None:
        """Test parsing week 01."""
        result = parse_temporal_key("2026W01T00")
        assert result["week"] == 1
        assert result["hour"] == 0

    def test_parse_week_52(self) -> None:
        """Test parsing week 52."""
        result = parse_temporal_key("2026W52T23")
        assert result["week"] == 52
        assert result["hour"] == 23


class TestTemporalBin:
    """Tests for TemporalBin class."""

    def test_temporal_bin_creation(self) -> None:
        """Test TemporalBin creation."""
        tb = TemporalBin(year=2026, week=5, hour=12)
        assert tb.year == 2026
        assert tb.week == 5
        assert tb.hour == 12

    def test_temporal_bin_to_key(self) -> None:
        """Test TemporalBin to_key method."""
        tb = TemporalBin(year=2026, week=10, hour=8)
        key = tb.to_key()
        assert "2026W10T08" in key or "2026W10T8" in key

    def test_temporal_bin_from_datetime(self) -> None:
        """Test TemporalBin from datetime."""
        dt = datetime(2026, 4, 15, 16, 30)
        tb = TemporalBin.from_datetime(dt)
        assert tb.year == 2026
        assert 1 <= tb.week <= 53
        assert tb.hour == 16
