"""Unit tests for contexts."""

from ucid.contexts.utils import merge_configs


def test_merge_configs():
    d1 = {"a": 1, "b": {"c": 2}}
    d2 = {"b": {"d": 3}}
    merged = merge_configs(d1, d2)
    assert merged["a"] == 1
    assert merged["b"]["c"] == 2
    assert merged["b"]["d"] == 3
