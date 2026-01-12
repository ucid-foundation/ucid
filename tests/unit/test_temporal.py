"""Unit tests for temporal."""
from ucid.temporal import trends

def test_linear_trend():
    slope, intercept, _ = trends.detect_linear_trend([1, 2, 3], [1, 2, 3])
    assert slope == pytest.approx(1.0)
    assert intercept == pytest.approx(0.0)
