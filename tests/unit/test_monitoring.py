"""Unit tests for Monitoring."""

from ucid.monitoring import health


def test_health():
    res = health.check_dependencies()
    assert res["database"] == "ok"
