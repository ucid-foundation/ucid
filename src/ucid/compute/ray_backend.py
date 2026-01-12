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

"""Ray distributed computing backend for UCID.

This module provides a Ray-based executor for distributed processing
across a cluster. Requires the optional `ray` dependency.
"""

from collections.abc import Callable, Iterable
from typing import Any

try:
    import ray  # type: ignore[import-untyped]
except ImportError:
    ray = None  # type: ignore[assignment]


class RayExecutor:
    """Ray distributed executor.

    Uses Ray for distributed parallel processing. Automatically
    initializes Ray if not already running.

    Example:
        >>> executor = RayExecutor()
        >>> results = executor.map(process_func, items)
        >>> executor.shutdown()
    """

    def __init__(self, **ray_init_kwargs: Any) -> None:
        """Initialize the Ray executor.

        Args:
            **ray_init_kwargs: Additional arguments passed to ray.init().

        Raises:
            ImportError: If ray is not installed.
        """
        if ray is None:
            raise ImportError("ray not installed - run: pip install ray")
        if not ray.is_initialized():
            ray.init(**ray_init_kwargs)

    def map(
        self,
        func: Callable[..., Any],
        items: Iterable[Any],
    ) -> list[Any]:
        """Apply a function to items in parallel using Ray.

        Args:
            func: Function to apply to each item.
            items: Iterable of items to process.

        Returns:
            List of results in the same order as items.
        """
        remote_func = ray.remote(func)
        futures = [remote_func.remote(item) for item in items]
        return ray.get(futures)

    def shutdown(self) -> None:
        """Shutdown the Ray runtime."""
        if ray is not None and ray.is_initialized():
            ray.shutdown()
