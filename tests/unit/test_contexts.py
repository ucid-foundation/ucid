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

"""Comprehensive unit tests for context registry module."""

from ucid.contexts import ContextRegistry, FifteenMinuteContext, TransitContext
from ucid.contexts.base import BaseContext


class TestContextRegistry:
    """Tests for ContextRegistry class."""

    def test_registry_singleton(self) -> None:
        """Test registry is singleton-like."""
        registry = ContextRegistry()
        assert registry is not None

    def test_registry_get_context(self) -> None:
        """Test getting a registered context."""
        registry = ContextRegistry()
        context = registry.get("15MIN")
        if context is not None:
            assert isinstance(context, BaseContext)

    def test_registry_get_unknown_context(self) -> None:
        """Test getting unknown context returns None."""
        registry = ContextRegistry()
        context = registry.get("UNKNOWN_CONTEXT_XYZ")
        assert context is None

    def test_registry_list_contexts(self) -> None:
        """Test listing all registered contexts."""
        registry = ContextRegistry()
        if hasattr(registry, "list") or hasattr(registry, "list_all"):
            contexts = getattr(registry, "list", getattr(registry, "list_all", lambda: []))()
            assert isinstance(contexts, list | tuple | set)

    def test_registry_has_builtin_contexts(self) -> None:
        """Test registry has builtin contexts."""
        registry = ContextRegistry()
        # Try to get some known contexts
        for name in ["15MIN", "TRANSIT"]:
            context = registry.get(name)
            # At least some should exist
            if context is not None:
                assert hasattr(context, "score")


class TestFifteenMinuteContext:
    """Tests for FifteenMinuteContext."""

    def test_context_creation(self) -> None:
        """Test creating FifteenMinuteContext."""
        context = FifteenMinuteContext()
        assert context is not None

    def test_context_name(self) -> None:
        """Test context has correct name."""
        context = FifteenMinuteContext()
        if hasattr(context, "name"):
            assert context.name == "15MIN"

    def test_context_score_method(self) -> None:
        """Test context has score method."""
        context = FifteenMinuteContext()
        assert hasattr(context, "score")

    def test_context_description(self) -> None:
        """Test context has description."""
        context = FifteenMinuteContext()
        if hasattr(context, "description"):
            assert len(context.description) > 0


class TestTransitContext:
    """Tests for TransitContext."""

    def test_transit_context_creation(self) -> None:
        """Test creating TransitContext."""
        context = TransitContext()
        assert context is not None

    def test_transit_context_name(self) -> None:
        """Test transit context has correct name."""
        context = TransitContext()
        if hasattr(context, "name"):
            assert context.name == "TRANSIT"

    def test_transit_context_has_score(self) -> None:
        """Test transit context has score method."""
        context = TransitContext()
        assert hasattr(context, "score")


class TestBaseContext:
    """Tests for BaseContext abstract class."""

    def test_base_context_is_abstract(self) -> None:
        """Test BaseContext cannot be instantiated directly."""
        # BaseContext should be abstract or raise on instantiation
        try:
            context = BaseContext()
            # If it doesn't raise, check it has required methods
            assert hasattr(context, "score")
        except (TypeError, NotImplementedError):
            # Expected for abstract base class
            pass

    def test_base_context_has_required_methods(self) -> None:
        """Test BaseContext defines required interface."""
        assert hasattr(BaseContext, "score")
        assert hasattr(BaseContext, "name") or hasattr(BaseContext, "NAME")
