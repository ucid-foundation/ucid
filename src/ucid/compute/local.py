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

"""Local thread-pool executor for UCID.

This module provides a local executor using Python's ThreadPoolExecutor
for parallel processing on a single machine.
"""

import concurrent.futures
from collections.abc import Callable, Iterable
from typing import Any

from ucid.compute.base import BaseExecutor


class LocalExecutor(BaseExecutor):
    """Local thread-pool executor.

    Uses Python's built-in ThreadPoolExecutor for parallel processing.
    Suitable for multi-core processing on a single machine.

    Attributes:
        max_workers: Maximum number of worker threads.

    Example:
        >>> executor = LocalExecutor(max_workers=4)
        >>> results = executor.map(process_func, items)
        >>> executor.shutdown()
    """

    def __init__(self, max_workers: int = 4) -> None:
        """Initialize the local executor.

        Args:
            max_workers: Maximum number of worker threads.
                Defaults to 4.
        """
        self.max_workers = max_workers
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

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
        return list(self._pool.map(func, items))

    def shutdown(self) -> None:
        """Clean up executor resources.

        Waits for all pending tasks to complete before returning.
        """
        self._pool.shutdown(wait=True)
