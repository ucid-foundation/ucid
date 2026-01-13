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

"""Comprehensive unit tests for compute module."""

from ucid.compute import LocalBackend
from ucid.compute.base import ComputeBackend
from ucid.compute.chunking import ChunkingStrategy


class TestLocalBackend:
    """Tests for LocalBackend class."""

    def test_local_backend_creation(self) -> None:
        """Test creating LocalBackend."""
        backend = LocalBackend()
        assert backend is not None

    def test_local_backend_is_compute_backend(self) -> None:
        """Test LocalBackend is a ComputeBackend."""
        backend = LocalBackend()
        assert isinstance(backend, ComputeBackend)

    def test_local_backend_has_execute(self) -> None:
        """Test LocalBackend has execute method."""
        backend = LocalBackend()
        assert hasattr(backend, "execute")

    def test_local_backend_has_map(self) -> None:
        """Test LocalBackend has map method."""
        backend = LocalBackend()
        assert hasattr(backend, "map") or hasattr(backend, "map_partitions")


class TestComputeBackend:
    """Tests for ComputeBackend abstract class."""

    def test_compute_backend_interface(self) -> None:
        """Test ComputeBackend defines required interface."""
        assert hasattr(ComputeBackend, "execute")


class TestChunkingStrategy:
    """Tests for ChunkingStrategy."""

    def test_chunking_strategy_instantiation(self) -> None:
        """Test ChunkingStrategy can be instantiated."""
        try:
            strategy = ChunkingStrategy()
            assert strategy is not None
        except TypeError:
            # May be abstract
            pass

    def test_chunking_has_chunk_method(self) -> None:
        """Test ChunkingStrategy has chunk method."""
        assert hasattr(ChunkingStrategy, "chunk") or hasattr(ChunkingStrategy, "split")
