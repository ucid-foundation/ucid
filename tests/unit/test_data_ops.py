"""Unit tests for data ops."""

import tempfile

from ucid.data import cache, provenance


def test_cache():
    with tempfile.TemporaryDirectory() as tmp:
        c = cache.Cache(tmp)
        c.set("key", "val")
        assert c.get("key") == "val"


def test_provenance():
    p = provenance.create_provenance("src", "mit")
    assert p.source == "src"
