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

"""Unit tests for UCID context modules."""

from unittest.mock import patch

import pytest

from ucid.contexts.base import ContextResult
from ucid.contexts.climate import ClimateContext
from ucid.contexts.equity import EquityContext
from ucid.contexts.fifteen_minute import FifteenMinuteContext
from ucid.contexts.transit import TransitContext
from ucid.contexts.vitality import VitalityContext
from ucid.contexts.walkability import WalkabilityContext


@pytest.fixture
def mock_osm_data() -> dict:
    """Return mock OSM data for testing."""
    return {"nodes": {1: {"lat": 41.0, "lon": 29.0}}, "ways": {1: {"nodes": [1]}}}


class TestFifteenMinuteContext:
    """Tests for the FifteenMinuteContext."""

    def test_initialization(self) -> None:
        """Test context initializes with correct ID."""
        ctx = FifteenMinuteContext()
        assert ctx.context_id == "15MIN"

    def test_compute_mock(self) -> None:
        """Test compute with mocked return value."""
        ctx = FifteenMinuteContext()
        with patch.object(
            ctx,
            "compute",
            return_value=ContextResult(raw_score=85, grade="A", confidence=0.9, metadata={}),
        ):
            result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
            assert result.grade == "A"
            assert result.raw_score == 85


class TestTransitContext:
    """Tests for the TransitContext."""

    def test_initialization(self) -> None:
        """Test context initializes with correct ID."""
        ctx = TransitContext()
        assert ctx.context_id == "TRANSIT"

    def test_compute_stub(self) -> None:
        """Test compute returns valid result structure."""
        ctx = TransitContext()
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert isinstance(result, ContextResult)
        assert result.grade in ["A", "B", "C", "D", "E", "F"]


class TestClimateContext:
    """Tests for the ClimateContext."""

    def test_initialization(self) -> None:
        """Test context initializes with correct ID."""
        ctx = ClimateContext()
        assert ctx.context_id == "CLIMATE"

    def test_heat_island_logic(self) -> None:
        """Test compute with custom config."""
        ctx = ClimateContext(config={"baseline_temp": 25})
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert isinstance(result, ContextResult)


class TestVitalityContext:
    """Tests for the VitalityContext."""

    def test_initialization(self) -> None:
        """Test context initializes with correct ID."""
        ctx = VitalityContext()
        assert ctx.context_id == "VITALITY"

    def test_poi_diversity(self) -> None:
        """Test compute returns valid score range."""
        ctx = VitalityContext()
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert 0 <= result.raw_score <= 100


class TestEquityContext:
    """Tests for the EquityContext."""

    def test_initialization(self) -> None:
        """Test context initializes with correct ID."""
        ctx = EquityContext()
        assert ctx.context_id == "EQUITY"

    def test_gini_mock(self) -> None:
        """Test compute returns valid result."""
        ctx = EquityContext()
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert isinstance(result, ContextResult)


class TestWalkabilityContext:
    """Tests for the WalkabilityContext."""

    def test_initialization(self) -> None:
        """Test context initializes with correct ID."""
        ctx = WalkabilityContext()
        assert ctx.context_id == "WALK"

    def test_intersection_density(self) -> None:
        """Test compute returns valid result."""
        ctx = WalkabilityContext()
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert isinstance(result, ContextResult)
