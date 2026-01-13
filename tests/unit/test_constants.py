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

"""Comprehensive unit tests for UCID constants."""

from ucid.core.constants import (
    BUILTIN_CONTEXTS,
    DEFAULT_H3_RESOLUTION,
    GRADE_THRESHOLDS,
    MAX_LAT,
    MAX_LON,
    MIN_LAT,
    MIN_LON,
    UCID_CURRENT_VERSION,
    UCID_VERSION_PREFIX,
    VALID_GRADES,
)


class TestVersionConstants:
    """Tests for version constants."""

    def test_version_prefix(self) -> None:
        """Test UCID version prefix."""
        assert UCID_VERSION_PREFIX == "UCID-"

    def test_current_version(self) -> None:
        """Test current UCID version."""
        assert UCID_CURRENT_VERSION == "V1"
        assert UCID_CURRENT_VERSION.startswith("V")


class TestH3Constants:
    """Tests for H3 constants."""

    def test_default_h3_resolution(self) -> None:
        """Test default H3 resolution."""
        assert DEFAULT_H3_RESOLUTION == 9
        assert 0 <= DEFAULT_H3_RESOLUTION <= 15


class TestGradeConstants:
    """Tests for grade constants."""

    def test_valid_grades(self) -> None:
        """Test valid grades list."""
        assert "A" in VALID_GRADES
        assert "B" in VALID_GRADES
        assert "C" in VALID_GRADES
        assert "D" in VALID_GRADES
        assert "F" in VALID_GRADES
        assert len(VALID_GRADES) >= 5

    def test_grade_thresholds(self) -> None:
        """Test grade thresholds."""
        assert isinstance(GRADE_THRESHOLDS, dict)
        assert "A" in GRADE_THRESHOLDS
        assert "F" in GRADE_THRESHOLDS

    def test_grade_thresholds_ordering(self) -> None:
        """Test that grade thresholds are properly ordered."""
        if "A" in GRADE_THRESHOLDS and "B" in GRADE_THRESHOLDS:
            assert GRADE_THRESHOLDS["A"] >= GRADE_THRESHOLDS["B"]


class TestCoordinateConstants:
    """Tests for coordinate constants."""

    def test_latitude_bounds(self) -> None:
        """Test latitude bounds."""
        assert MIN_LAT == -90.0
        assert MAX_LAT == 90.0

    def test_longitude_bounds(self) -> None:
        """Test longitude bounds."""
        assert MIN_LON == -180.0
        assert MAX_LON == 180.0

    def test_bounds_consistency(self) -> None:
        """Test bounds are consistent."""
        assert MIN_LAT < MAX_LAT
        assert MIN_LON < MAX_LON


class TestContextConstants:
    """Tests for context constants."""

    def test_builtin_contexts(self) -> None:
        """Test builtin contexts."""
        assert isinstance(BUILTIN_CONTEXTS, list | tuple | set | dict)
        # Should have at least one builtin context
        assert len(BUILTIN_CONTEXTS) > 0

    def test_15min_context(self) -> None:
        """Test 15MIN context is builtin."""
        # 15MIN is a core context
        assert "15MIN" in BUILTIN_CONTEXTS or "15MIN" in str(BUILTIN_CONTEXTS)
