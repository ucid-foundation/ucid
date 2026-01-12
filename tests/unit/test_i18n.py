"""Unit tests for i18n."""
from ucid.i18n import messages

def test_get_message():
    assert messages.get_message("hello", "en") == "Hello"
    assert messages.get_message("hello", "es") == "Hola"
