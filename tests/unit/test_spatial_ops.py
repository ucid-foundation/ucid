"""Unit tests for spatial ops."""

from ucid.spatial import aggregation, crs


def test_haversine():
    dist = crs.CRSops.haversine_distance(0, 0, 0, 1)
    assert 111000 < dist < 112000  # Approx 111km


def test_aggregation():
    assert aggregation.aggregate_scores([10, 20, 30]) == 20.0
