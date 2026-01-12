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

"""Caching layer for UCID data operations.

This module provides a file-based caching mechanism to store and retrieve
computed results, reducing redundant API calls and expensive computations.
"""

import hashlib
import pickle
import shutil
import time
from pathlib import Path
from typing import Any


class Cache:
    """File-based cache with expiration support.

    Provides production-grade caching for arbitrary Python objects using
    pickle serialization. Supports automatic expiration of cached items.

    Attributes:
        cache_dir: Path to the cache directory.
        expiry: Expiration time in seconds.

    Example:
        >>> cache = Cache(cache_dir=".ucid_cache", expiry_seconds=3600)
        >>> cache.set("my_key", {"data": [1, 2, 3]})
        >>> result = cache.get("my_key")
    """

    def __init__(
        self,
        cache_dir: str = ".ucid_cache",
        expiry_seconds: int = 3600,
    ) -> None:
        """Initialize the cache.

        Args:
            cache_dir: Directory path for storing cache files.
            expiry_seconds: Time in seconds before cache entries expire.
                Defaults to 3600 (1 hour).
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.expiry = expiry_seconds

    def _get_path(self, key: str) -> Path:
        """Get the file path for a cache key.

        Args:
            key: The cache key to hash.

        Returns:
            Path to the cache file for this key.
        """
        hashed = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{hashed}.pkl"

    def get(self, key: str) -> Any | None:
        """Get a value from the cache.

        Args:
            key: The cache key to retrieve.

        Returns:
            The cached value, or None if not found or expired.
        """
        path = self._get_path(key)
        if not path.exists():
            return None

        try:
            # Check modification time for expiry
            mtime = path.stat().st_mtime
            if time.time() - mtime > self.expiry:
                path.unlink(missing_ok=True)
                return None

            with open(path, "rb") as f:
                return pickle.load(f)  # noqa: S301
        except (pickle.PickleError, EOFError, OSError):
            return None

    def set(self, key: str, value: Any) -> None:
        """Store a value in the cache.

        Args:
            key: The cache key.
            value: The value to cache (must be picklable).
        """
        path = self._get_path(key)
        try:
            with open(path, "wb") as f:
                pickle.dump(value, f)
        except (pickle.PickleError, OSError):
            pass  # Fail silently on cache write errors

    def clear(self) -> None:
        """Clear all cached data.

        Removes all files from the cache directory.
        """
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir()
