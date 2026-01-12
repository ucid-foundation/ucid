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

"""Client-side exceptions for UCID API client.

This module defines custom exceptions for the UCID client library
to enable specific error handling.
"""


class UCIDClientError(Exception):
    """Base exception for UCID client errors.

    All client-specific exceptions inherit from this class,
    allowing callers to catch all client errors with a single except clause.

    Example:
        >>> try:
        ...     client.parse(invalid_ucid)
        ... except UCIDClientError as e:
        ...     print(f"Client error: {e}")
    """


class UCIDConnectionError(UCIDClientError):
    """Connection to the UCID API failed.

    Raised when the client cannot establish a connection to the
    API server, typically due to network issues or server unavailability.

    Attributes:
        url: The URL that failed to connect.
        cause: The underlying exception that caused the failure.
    """

    def __init__(
        self,
        message: str,
        url: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize the connection error.

        Args:
            message: Human-readable error message.
            url: The URL that failed to connect.
            cause: The underlying exception.
        """
        super().__init__(message)
        self.url = url
        self.cause = cause


class UCIDAPIError(UCIDClientError):
    """API returned an error response.

    Raised when the API returns a non-success status code.

    Attributes:
        status_code: HTTP status code returned.
        response_body: Response body content.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: str | None = None,
    ) -> None:
        """Initialize the API error.

        Args:
            message: Human-readable error message.
            status_code: HTTP status code.
            response_body: Response body for debugging.
        """
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body
