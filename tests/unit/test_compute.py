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

"""Unit tests for compute module."""

from ucid.compute.backpressure import RateLimiter
from ucid.compute.chunking import chunk_list


def test_chunking() -> None:
    """Test list chunking functionality."""
    chunks = list(chunk_list([1, 2, 3, 4], 2))
    assert len(chunks) == 2
    assert chunks[0] == [1, 2]


def test_backpressure() -> None:
    """Test rate limiter acquires without blocking."""
    rl = RateLimiter(100)
    rl.acquire()  # Should return immediately
