"""Unit tests for Utils."""
from ucid.utils.config import Config
import os

def test_config():
    os.environ["TEST_KEY"] = "val"
    assert Config.get("TEST_KEY") == "val"
