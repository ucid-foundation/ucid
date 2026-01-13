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

"""Tests for UCID contexts module."""

from ucid.contexts import (
    ClimateContext,
    ContextResult,
    EquityContext,
    FifteenMinuteContext,
    TransitContext,
    VitalityContext,
    WalkabilityContext,
)


class TestContextResult:
    """Tests for ContextResult dataclass."""

    def test_create_result(self) -> None:
        """ContextResult should be created with required fields."""
        result = ContextResult(
            raw_score=75.0,
            grade="B",
            confidence=0.8,
        )
        assert result.raw_score == 75.0
        assert result.grade == "B"
        assert result.confidence == 0.8

    def test_default_fields(self) -> None:
        """Default fields should be set correctly."""
        result = ContextResult(raw_score=50.0, grade="D", confidence=0.5)
        assert result.uncertainty == 0.0
        assert result.data_sources == []
        assert result.artifacts == {}
        assert result.metadata == {}


class TestFifteenMinuteContext:
    """Tests for 15-Minute City context."""

    def test_context_id(self) -> None:
        """Context ID should be 15MIN."""
        ctx = FifteenMinuteContext()
        assert ctx.context_id == "15MIN"

    def test_compute_returns_result(self) -> None:
        """Compute should return a ContextResult."""
        ctx = FifteenMinuteContext()
        result = ctx.compute(lat=41.015, lon=28.979, timestamp="2026W01T12")
        assert isinstance(result, ContextResult)
        assert 0 <= result.raw_score <= 100
        assert result.grade in ("A+", "A", "B", "C", "D", "F")


class TestTransitContext:
    """Tests for Transit context."""

    def test_context_id(self) -> None:
        """Context ID should be TRANSIT."""
        ctx = TransitContext()
        assert ctx.context_id == "TRANSIT"


class TestClimateContext:
    """Tests for Climate context."""

    def test_context_id(self) -> None:
        """Context ID should be CLIMATE."""
        ctx = ClimateContext()
        assert ctx.context_id == "CLIMATE"


class TestVitalityContext:
    """Tests for Vitality context."""

    def test_context_id(self) -> None:
        """Context ID should be VITALITY."""
        ctx = VitalityContext()
        assert ctx.context_id == "VITALITY"


class TestEquityContext:
    """Tests for Equity context."""

    def test_context_id(self) -> None:
        """Context ID should be EQUITY."""
        ctx = EquityContext()
        assert ctx.context_id == "EQUITY"


class TestWalkabilityContext:
    """Tests for Walkability context."""

    def test_context_id(self) -> None:
        """Context ID should be WALK."""
        ctx = WalkabilityContext()
        assert ctx.context_id == "WALK"


class TestGradeScore:
    """Tests for grade score conversion."""

    def test_grade_thresholds(self) -> None:
        """Grade thresholds should be correct."""
        ctx = FifteenMinuteContext()
        assert ctx.grade_score(95) == "A+"
        assert ctx.grade_score(85) == "A"
        assert ctx.grade_score(75) == "B"
        assert ctx.grade_score(65) == "C"
        assert ctx.grade_score(55) == "D"
        assert ctx.grade_score(45) == "F"
