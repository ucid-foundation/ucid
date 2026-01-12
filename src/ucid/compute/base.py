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

"""Base executor interface for distributed compute.

This module defines the abstract interface for UCID executors,
which provide parallel processing capabilities for large-scale
urban analysis operations.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from typing import Any


class BaseExecutor(ABC):
    """Abstract base class for UCID compute executors.

    Executors provide parallel processing capabilities for UCID
    operations. Implementations include local thread pools,
    Dask distributed clusters, and Ray.

    Subclasses must implement the `map` and `shutdown` methods.

    Example:
        >>> class MyExecutor(BaseExecutor):
        ...     def map(self, func, items):
        ...         return [func(item) for item in items]
        ...     def shutdown(self):
        ...         pass
    """

    @abstractmethod
    def map(
        self,
        func: Callable[..., Any],
        items: Iterable[Any],
    ) -> list[Any]:
        """Apply a function to items in parallel.

        Args:
            func: Function to apply to each item.
            items: Iterable of items to process.

        Returns:
            List of results in the same order as items.
        """

    @abstractmethod
    def shutdown(self) -> None:
        """Clean up executor resources.

        Should be called when the executor is no longer needed
        to release threads, connections, or other resources.
        """
