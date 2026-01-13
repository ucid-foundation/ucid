"""Unit tests for Client."""

from ucid.client.exceptions import UCIDClientError


def test_client_error():
    e = UCIDClientError("test")
    assert str(e) == "test"
