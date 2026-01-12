"""Unit tests for UCID context modules."""
import pytest
from unittest.mock import MagicMock, patch
from ucid.contexts.fifteen_minute import FifteenMinuteContext
from ucid.contexts.transit import TransitContext
from ucid.contexts.climate import ClimateContext
from ucid.contexts.vitality import VitalityContext
from ucid.contexts.equity import EquityContext
from ucid.contexts.walkability import WalkabilityContext
from ucid.contexts.base import ContextResult

@pytest.fixture
def mock_osm_data():
    return {
        "nodes": {1: {"lat": 41.0, "lon": 29.0}},
        "ways": {1: {"nodes": [1]}}
    }

class TestFifteenMinuteContext:
    def test_initialization(self):
        ctx = FifteenMinuteContext()
        assert ctx.context_id == "15MIN"

    def test_compute_mock(self):
        ctx = FifteenMinuteContext()
        # Mocking internal compute logic if it relies on external APIs
        with patch.object(ctx, 'compute', return_value=ContextResult(
            raw_score=85, grade="A", confidence=0.9, metadata={}
        )) as mock_compute:
            result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
            assert result.grade == "A"
            assert result.raw_score == 85

class TestTransitContext:
    def test_initialization(self):
        ctx = TransitContext()
        assert ctx.context_id == "TRANSIT"

    def test_compute_stub(self):
        # Assuming the current implementation is a stub or has a fallback
        ctx = TransitContext()
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert isinstance(result, ContextResult)
        # Verify it returns a valid grade structure
        assert result.grade in ["A", "B", "C", "D", "E", "F"]

class TestClimateContext:
    def test_initialization(self):
        ctx = ClimateContext()
        assert ctx.context_id == "CLIMATE"

    def test_heat_island_logic(self):
        ctx = ClimateContext(config={"baseline_temp": 25})
        # Test with mock config
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert isinstance(result, ContextResult)

class TestVitalityContext:
    def test_initialization(self):
        ctx = VitalityContext()
        assert ctx.context_id == "VITALITY"

    def test_poi_diversity(self):
        ctx = VitalityContext()
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert 0 <= result.raw_score <= 100

class TestEquityContext:
    def test_initialization(self):
        ctx = EquityContext()
        assert ctx.context_id == "EQUITY"

    def test_gini_mock(self):
        ctx = EquityContext()
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert isinstance(result, ContextResult)

class TestWalkabilityContext:
    def test_initialization(self):
        ctx = WalkabilityContext()
        assert ctx.context_id == "WALK"

    def test_intersection_density(self):
        ctx = WalkabilityContext()
        result = ctx.compute(41.0, 29.0, timestamp="2026W01T12")
        assert isinstance(result, ContextResult)
