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

"""Comprehensive unit tests for scoring module."""

import pytest

from ucid.scoring import (
    grade_to_score_range,
    min_max_normalize,
    normalize_score,
    score_to_grade,
    z_score_normalize,
)


class TestNormalizeScore:
    """Tests for normalize_score function."""

    def test_normalize_basic(self) -> None:
        """Test basic normalization."""
        result = normalize_score(50, min_val=0, max_val=100)
        assert 0.0 <= result <= 1.0

    def test_normalize_min_value(self) -> None:
        """Test normalizing minimum value."""
        result = normalize_score(0, min_val=0, max_val=100)
        assert result == 0.0

    def test_normalize_max_value(self) -> None:
        """Test normalizing maximum value."""
        result = normalize_score(100, min_val=0, max_val=100)
        assert result == 1.0

    def test_normalize_mid_range(self) -> None:
        """Test normalizing mid-range value."""
        result = normalize_score(50, min_val=0, max_val=100)
        assert result == pytest.approx(0.5)


class TestMinMaxNormalize:
    """Tests for min_max_normalize function."""

    def test_min_max_basic(self) -> None:
        """Test basic min-max normalization."""
        values = [10, 20, 30, 40, 50]
        result = min_max_normalize(values)
        assert len(result) == len(values)
        assert min(result) == 0.0
        assert max(result) == 1.0

    def test_min_max_single_value(self) -> None:
        """Test min-max with single value."""
        result = min_max_normalize([50])
        assert len(result) == 1

    def test_min_max_uniform_values(self) -> None:
        """Test min-max with uniform values."""
        result = min_max_normalize([50, 50, 50])
        assert len(result) == 3

    def test_min_max_negative_values(self) -> None:
        """Test min-max with negative values."""
        values = [-10, 0, 10, 20]
        result = min_max_normalize(values)
        assert min(result) == 0.0
        assert max(result) == 1.0


class TestZScoreNormalize:
    """Tests for z_score_normalize function."""

    def test_z_score_basic(self) -> None:
        """Test basic z-score normalization."""
        values = [10, 20, 30, 40, 50]
        result = z_score_normalize(values)
        assert len(result) == len(values)

    def test_z_score_mean_is_zero(self) -> None:
        """Test z-score mean is approximately zero."""
        values = [10, 20, 30, 40, 50]
        result = z_score_normalize(values)
        mean = sum(result) / len(result)
        assert abs(mean) < 1e-10

    def test_z_score_single_value(self) -> None:
        """Test z-score with single value."""
        result = z_score_normalize([50])
        assert len(result) == 1


class TestScoreToGrade:
    """Tests for score_to_grade function."""

    def test_score_to_grade_a(self) -> None:
        """Test high score gets grade A."""
        grade = score_to_grade(0.95)
        assert grade == "A" or grade == "A+"

    def test_score_to_grade_f(self) -> None:
        """Test low score gets grade F."""
        grade = score_to_grade(0.1)
        assert grade == "F" or grade == "D"

    def test_score_to_grade_middle(self) -> None:
        """Test middle score."""
        grade = score_to_grade(0.5)
        assert grade in ["A", "B", "C", "D", "F"]

    def test_score_to_grade_zero(self) -> None:
        """Test zero score."""
        grade = score_to_grade(0.0)
        assert grade in ["D", "F"]

    def test_score_to_grade_one(self) -> None:
        """Test perfect score."""
        grade = score_to_grade(1.0)
        assert grade in ["A", "A+"]


class TestGradeToScoreRange:
    """Tests for grade_to_score_range function."""

    def test_grade_a_range(self) -> None:
        """Test grade A score range."""
        score_range = grade_to_score_range("A")
        assert isinstance(score_range, tuple)
        assert len(score_range) == 2
        assert score_range[0] < score_range[1]

    def test_grade_f_range(self) -> None:
        """Test grade F score range."""
        score_range = grade_to_score_range("F")
        assert isinstance(score_range, tuple)
        assert score_range[0] >= 0.0

    def test_all_grades_have_ranges(self) -> None:
        """Test all grades have valid ranges."""
        for grade in ["A", "B", "C", "D", "F"]:
            score_range = grade_to_score_range(grade)
            assert isinstance(score_range, tuple)
            assert len(score_range) == 2
