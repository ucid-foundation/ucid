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

"""Dask distributed computing backend for UCID.

This module provides a Dask-based executor for distributed processing
across a cluster. Requires the optional `dask[distributed]` dependency.
"""

from collections.abc import Callable, Iterable
from typing import Any

try:
    import dask  # type: ignore[import-untyped]
    from dask import distributed as dask_distributed  # type: ignore[import-untyped]
except ImportError:
    dask = None  # type: ignore[assignment]
    dask_distributed = None  # type: ignore[assignment]


class DaskExecutor:
    """Dask distributed executor.

    Connects to a Dask scheduler and distributes work across workers.
    Use this for large-scale processing across multiple machines.

    Attributes:
        client: The Dask distributed client.

    Example:
        >>> executor = DaskExecutor(scheduler_address="tcp://scheduler:8786")
        >>> results = executor.map(process_func, items)
        >>> executor.shutdown()
    """

    def __init__(self, scheduler_address: str | None = None) -> None:
        """Initialize the Dask executor.

        Args:
            scheduler_address: Address of the Dask scheduler.
                If None, creates a local cluster.

        Raises:
            ImportError: If dask[distributed] is not installed.
        """
        if dask is None or dask_distributed is None:
            raise ImportError("dask[distributed] not installed - run: pip install dask[distributed]")
        self.client = dask_distributed.Client(scheduler_address)

    def map(
        self,
        func: Callable[..., Any],
        items: Iterable[Any],
    ) -> list[Any]:
        """Apply a function to items in parallel across the cluster.

        Args:
            func: Function to apply to each item.
            items: Iterable of items to process.

        Returns:
            List of results in the same order as items.
        """
        futures = self.client.map(func, items)
        return self.client.gather(futures)

    def shutdown(self) -> None:
        """Close the Dask client connection."""
        self.client.close()
