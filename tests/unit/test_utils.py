"""Unit tests for Utils."""

import os

from ucid.utils.config import Config


def test_config():
    os.environ["TEST_KEY"] = "val"
    assert Config.get("TEST_KEY") == "val"
