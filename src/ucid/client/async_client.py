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

"""Asynchronous Python client for UCID API.

This module provides an async HTTP client for interacting with
the UCID API service using aiohttp.

Example:
    >>> async with AsyncUCIDClient("http://localhost:8000") as client:
    ...     result = await client.health()
    ...     print(result["status"])
"""

from typing import Any

try:
    import aiohttp  # type: ignore[import-untyped]
except ImportError:
    aiohttp = None  # type: ignore[assignment]


class AsyncUCIDClient:
    """Asynchronous client for the UCID API service.

    Provides async methods for UCID operations. Must be used as
    an async context manager.

    Attributes:
        base_url: Base URL of the UCID API service.

    Example:
        >>> async with AsyncUCIDClient() as client:
        ...     health = await client.health()
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
    ) -> None:
        """Initialize the async UCID client.

        Args:
            base_url: Base URL of the UCID API service.
            api_key: Optional API key for authentication.
        """
        if aiohttp is None:
            raise ImportError("aiohttp not installed - run: pip install aiohttp")
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "AsyncUCIDClient":
        """Enter async context manager and create session."""
        headers = {"X-API-Key": self._api_key} if self._api_key else {}
        self._session = aiohttp.ClientSession(headers=headers)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Exit async context manager and close session."""
        if self._session:
            await self._session.close()

    async def health(self) -> dict[str, Any]:
        """Check API health status asynchronously.

        Returns:
            Health status dictionary.

        Raises:
            RuntimeError: If client not initialized via async context manager.
        """
        if not self._session:
            raise RuntimeError("Client not initialized (use 'async with')")
        async with self._session.get(f"{self.base_url}/v1/health") as resp:
            return await resp.json()

    async def parse(self, ucid_string: str) -> dict[str, Any]:
        """Parse a UCID string asynchronously.

        Args:
            ucid_string: UCID string to parse.

        Returns:
            Dictionary with parsed UCID details.

        Raises:
            RuntimeError: If client not initialized.
        """
        if not self._session:
            raise RuntimeError("Client not initialized (use 'async with')")
        async with self._session.post(
            f"{self.base_url}/v1/ucid/parse",
            params={"ucid_string": ucid_string},
        ) as resp:
            return await resp.json()
