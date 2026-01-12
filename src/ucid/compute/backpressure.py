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

"""Backpressure and rate limiting for UCID compute operations.

This module provides rate limiting utilities to prevent overwhelming
external services or compute resources during large-scale operations.
"""

import time


class RateLimiter:
    """Token bucket rate limiter.

    Implements a simple token bucket algorithm for rate limiting.
    Tokens are replenished at a constant rate, and operations
    consume tokens. If no tokens are available, the caller blocks
    until a token becomes available.

    Attributes:
        rate: Tokens per second.
        tokens: Current available tokens.

    Example:
        >>> limiter = RateLimiter(rate_per_second=10.0)
        >>> for item in items:
        ...     limiter.acquire()  # Blocks if rate exceeded
        ...     process(item)
    """

    def __init__(self, rate_per_second: float) -> None:
        """Initialize the rate limiter.

        Args:
            rate_per_second: Maximum operations per second.
        """
        self.rate = rate_per_second
        self.tokens = rate_per_second
        self._last_update = time.monotonic()

    def acquire(self) -> None:
        """Acquire a token, blocking if necessary.

        Blocks until a token is available. Uses a polling loop
        with a 100ms sleep to minimize CPU usage while waiting.
        """
        while True:
            now = time.monotonic()
            elapsed = now - self._last_update
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self._last_update = now

            if self.tokens >= 1:
                self.tokens -= 1
                return
            time.sleep(0.1)

    def try_acquire(self) -> bool:
        """Try to acquire a token without blocking.

        Returns:
            True if a token was acquired, False otherwise.
        """
        now = time.monotonic()
        elapsed = now - self._last_update
        self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
        self._last_update = now

        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False
