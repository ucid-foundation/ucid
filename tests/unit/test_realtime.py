"""Unit tests for realtime."""

from ucid.realtime.windowing import TumblingWindow


def test_windowing():
    w = TumblingWindow(2)
    assert not w.add(1)
    assert w.add(2)  # Window closed
    assert w.flush() == []  # Already flushed on close? No, implementation depends
