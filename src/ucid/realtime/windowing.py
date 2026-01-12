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

"""Windowed aggregation for streaming data.

This module provides window implementations for aggregating
streaming events over fixed or sliding time/count windows.
"""

from typing import Any


class TumblingWindow:
    """Fixed-size non-overlapping window.

    Collects items until the window size is reached, then emits all items.
    Windows do not overlap - each item belongs to exactly one window.

    Attributes:
        size: Maximum number of items in the window.

    Example:
        >>> window = TumblingWindow(size=3)
        >>> window.add({"score": 80})  # False
        >>> window.add({"score": 85})  # False
        >>> window.add({"score": 90})  # True (window closed)
        >>> items = window.flush()
    """

    def __init__(self, size: int) -> None:
        """Initialize the tumbling window.

        Args:
            size: Number of items before the window closes.
        """
        self.size = size
        self._current: list[Any] = []

    def add(self, item: Any) -> bool:
        """Add an item to the window.

        Args:
            item: Item to add.

        Returns:
            True if the window is now full and ready to flush.
        """
        self._current.append(item)
        return len(self._current) >= self.size

    def flush(self) -> list[Any]:
        """Flush and return all items in the window.

        Returns:
            List of items that were in the window.
        """
        result = self._current
        self._current = []
        return result

    def count(self) -> int:
        """Get the current number of items in the window.

        Returns:
            Number of items currently in the window.
        """
        return len(self._current)


class SlidingWindow:
    """Fixed-size sliding window with overlap.

    Maintains a maximum number of recent items.

    Example:
        >>> window = SlidingWindow(max_size=5)
        >>> for i in range(10):
        ...     window.add(i)
        >>> print(window.items())  # [5, 6, 7, 8, 9]
    """

    def __init__(self, max_size: int) -> None:
        """Initialize the sliding window.

        Args:
            max_size: Maximum number of items to retain.
        """
        self.max_size = max_size
        self._items: list[Any] = []

    def add(self, item: Any) -> None:
        """Add an item to the window.

        Args:
            item: Item to add.
        """
        self._items.append(item)
        if len(self._items) > self.max_size:
            self._items.pop(0)

    def items(self) -> list[Any]:
        """Get all items in the window.

        Returns:
            List of items currently in the window.
        """
        return list(self._items)
