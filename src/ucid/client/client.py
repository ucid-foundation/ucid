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

"""Synchronous Python client for UCID API.

This module provides a synchronous HTTP client for interacting
with the UCID API service using httpx.

Example:
    >>> with UCIDClient("http://localhost:8000") as client:
    ...     result = client.parse("UCID-V1:IST:+41.015:+28.979:...")
    ...     print(result["city"])
"""

from typing import Any

import httpx


class UCIDClient:
    """Synchronous client for the UCID API service.

    Provides methods for parsing and creating UCIDs via the REST API.
    Use as a context manager for automatic resource cleanup.

    Attributes:
        base_url: Base URL of the UCID API service.
        timeout: Request timeout in seconds.

    Example:
        >>> client = UCIDClient("http://localhost:8000")
        >>> result = client.parse("UCID-V1:IST:+41.015:+28.979:...")
        >>> client.close()
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 30.0,
        api_key: str | None = None,
    ) -> None:
        """Initialize the UCID client.

        Args:
            base_url: Base URL of the UCID API service.
            timeout: Request timeout in seconds. Defaults to 30.0.
            api_key: Optional API key for authentication.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        headers = {"X-API-Key": api_key} if api_key else {}
        self._client = httpx.Client(timeout=timeout, headers=headers)

    def parse(self, ucid_string: str) -> dict[str, Any]:
        """Parse a UCID string via the API.

        Args:
            ucid_string: UCID string to parse.

        Returns:
            Dictionary with parsed UCID details including city,
            coordinates, timestamp, context, and grade.

        Raises:
            httpx.HTTPStatusError: If the request fails.
        """
        response = self._client.post(
            f"{self.base_url}/v1/ucid/parse",
            params={"ucid_string": ucid_string},
        )
        response.raise_for_status()
        return response.json()

    def create(
        self,
        city: str,
        lat: float,
        lon: float,
        timestamp: str,
        context: str,
        grade: str = "F",
        confidence: float = 0.0,
    ) -> dict[str, Any]:
        """Create a UCID via the API.

        Args:
            city: 3-character city code (e.g., IST, NYC).
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            timestamp: ISO week timestamp (e.g., 2026W01T12).
            context: Context identifier (e.g., 15MIN, TRANSIT).
            grade: Quality grade. Defaults to "F".
            confidence: Confidence score (0.0-1.0). Defaults to 0.0.

        Returns:
            Dictionary with created UCID details.

        Raises:
            httpx.HTTPStatusError: If the request fails.
        """
        response = self._client.post(
            f"{self.base_url}/v1/ucid/create",
            json={
                "city": city,
                "lat": lat,
                "lon": lon,
                "timestamp": timestamp,
                "context": context,
                "grade": grade,
                "confidence": confidence,
            },
        )
        response.raise_for_status()
        return response.json()

    def health(self) -> dict[str, str]:
        """Check API health status.

        Returns:
            Health status dictionary with status and version.
        """
        response = self._client.get(f"{self.base_url}/v1/health")
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        """Close the HTTP client and release resources."""
        self._client.close()

    def __enter__(self) -> "UCIDClient":
        """Enter context manager."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Exit context manager and close client."""
        self.close()
