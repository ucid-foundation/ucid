"""Unit tests for scoring."""

from ucid.scoring import sensitivity


def test_sensitivity():
    def func(x):
        return x * 2

    res = sensitivity.analyze_sensitivity(func, {"x": 1}, {"x": [1, 2, 3]})
    assert res["baseline"] == 2
    assert res["variations"]["x"] == [2, 4, 6]
