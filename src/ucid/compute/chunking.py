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

"""Data chunking strategies for distributed processing.

This module provides utilities for splitting data into chunks
suitable for parallel processing across multiple workers.
"""

from collections.abc import Iterator
from typing import TypeVar

T = TypeVar("T")


def chunk_list(items: list[T], chunk_size: int) -> Iterator[list[T]]:
    """Split a list into fixed-size chunks.

    Yields successive chunks of the specified size. The last chunk
    may be smaller if the list length is not evenly divisible.

    Args:
        items: List of items to chunk.
        chunk_size: Maximum size of each chunk. Must be positive.

    Yields:
        Lists of at most chunk_size items.

    Raises:
        ValueError: If chunk_size is less than 1.

    Example:
        >>> list(chunk_list([1, 2, 3, 4, 5], 2))
        [[1, 2], [3, 4], [5]]
    """
    if chunk_size < 1:
        raise ValueError("chunk_size must be at least 1")

    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]


def chunk_count(total: int, num_chunks: int) -> list[int]:
    """Calculate chunk sizes for splitting total items evenly.

    Distributes items as evenly as possible across the specified
    number of chunks.

    Args:
        total: Total number of items to distribute.
        num_chunks: Number of chunks to create.

    Returns:
        List of chunk sizes.

    Example:
        >>> chunk_count(10, 3)
        [4, 3, 3]
    """
    base_size = total // num_chunks
    remainder = total % num_chunks
    return [base_size + (1 if i < remainder else 0) for i in range(num_chunks)]
