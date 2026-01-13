# Copyright 2026 UCID Foundation
#
# Licensed under the EUPL, Version 1.2 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for data operations."""

import tempfile

from ucid.data import cache, provenance


def test_cache() -> None:
    """Test cache set and get operations."""
    with tempfile.TemporaryDirectory() as tmp:
        c = cache.Cache(tmp)
        c.set("key", "val")
        assert c.get("key") == "val"


def test_provenance() -> None:
    """Test provenance record creation."""
    p = provenance.create_provenance("src", "mit")
    assert p.source == "src"
