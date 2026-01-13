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

"""Context registry for discovering and loading context plugins.

This module provides a registry that discovers context implementations
via Python entry points, enabling a pluggable architecture for custom
contexts.

Example:
    >>> from ucid.contexts.registry import ContextRegistry
    >>> registry = ContextRegistry()
    >>> context_cls = registry.get_context_class("15MIN")
    >>> context = context_cls()
    >>> result = context.compute(lat=41.015, lon=28.979, timestamp="2026W01T12")
"""

from importlib.metadata import entry_points

from ucid.contexts.base import BaseContext
from ucid.core.errors import UCIDContextError


class ContextRegistry:
    """Registry for discovering and loading context plugins.

    This class implements the Singleton pattern to maintain a global
    registry of available contexts. Contexts are discovered via the
    `ucid.contexts` entry point group.

    Attributes:
        _contexts: Internal dictionary mapping context IDs to classes.
    """

    _instance: "ContextRegistry | None" = None

    def __new__(cls) -> "ContextRegistry":
        """Create or return the singleton instance."""
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._contexts: dict[str, type[BaseContext]] = {}
            instance._discover()
            cls._instance = instance
        return cls._instance

    def _discover(self) -> None:
        """Discover context plugins via entry points."""
        try:
            eps = entry_points(group="ucid.contexts")
            for ep in eps:
                try:
                    ctx_cls = ep.load()
                    if isinstance(ctx_cls, type) and issubclass(ctx_cls, BaseContext):
                        self._contexts[ep.name.upper()] = ctx_cls
                except Exception:
                    pass
        except Exception:
            pass

    def register(self, context_cls: type[BaseContext]) -> None:
        """Manually register a context class.

        Args:
            context_cls: Context class to register.
        """
        instance = context_cls()
        self._contexts[instance.context_id.upper()] = context_cls

    def get_context_class(self, name: str) -> type[BaseContext]:
        """Get a context class by name.

        Args:
            name: Context identifier (case-insensitive).

        Returns:
            Context class.

        Raises:
            UCIDContextError: If context is not found.
        """
        name_upper = name.upper()
        if name_upper not in self._contexts:
            raise UCIDContextError(
                f"Context '{name_upper}' not found.",
                code="CONTEXT_NOT_FOUND",
                details={"context": name_upper, "available": self.list_contexts()},
            )
        return self._contexts[name_upper]

    def list_contexts(self) -> list[str]:
        """List all registered context IDs.

        Returns:
            List of context identifier strings.
        """
        return list(self._contexts.keys())

    def has_context(self, name: str) -> bool:
        """Check if a context is registered.

        Args:
            name: Context identifier.

        Returns:
            True if context exists, False otherwise.
        """
        return name.upper() in self._contexts
