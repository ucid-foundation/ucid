"""Unit tests for Viz."""

from ucid.viz import themes


def test_themes():
    t = themes.get_theme()
    assert "primary_color" in t
