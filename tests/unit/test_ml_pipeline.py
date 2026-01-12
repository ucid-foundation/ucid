"""Unit tests for ML."""
from ucid.ml.features import FeaturePipeline
from ucid.ml.evaluation import calculate_metrics

def test_metrics():
    res = calculate_metrics([1.0], [1.0])
    assert res["mse"] == 0.0

def test_pipeline():
    fp = FeaturePipeline()
    assert fp.fit([]).transform([]).shape == (1, 1)
