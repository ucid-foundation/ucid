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

"""Custom exceptions for the UCID library.

This module defines the exception hierarchy used throughout the UCID package.
All UCID-specific exceptions inherit from UCIDError, which allows users to
catch all UCID errors with a single except clause.

Example:
    >>> try:
    ...     parse_ucid("invalid-string")
    ... except UCIDError as e:
    ...     print(f"Error: {e.error_code} - {e.message}")
"""

from typing import Any


class UCIDError(Exception):
    """Base exception for all UCID errors.

    Attributes:
        error_code: A stable string code identifying the error type.
        message: Human-readable error message.
        details: Optional dictionary with additional context.
    """

    error_code: str = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        code: str | None = None,
    ) -> None:
        """Initialize UCIDError.

        Args:
            message: Human-readable error message.
            details: Optional dictionary with additional context about the error.
            code: Optional error code to override the class default.
        """
        self.message = message
        self.details = details or {}
        if code:
            self.error_code = code
        super().__init__(self.message)

    def __repr__(self) -> str:
        """Return string representation."""
        return f"{self.__class__.__name__}(code={self.error_code!r}, message={self.message!r})"


class UCIDParseError(UCIDError):
    """Raised when a UCID string cannot be parsed.

    This error indicates that the input string does not conform to the
    UCID format specification.
    """

    error_code = "PARSE_ERROR"


class UCIDValidationError(UCIDError):
    """Raised when a UCID fails validation rules.

    This error indicates that while the UCID string is parseable, it
    violates semantic validation rules (e.g., invalid city code,
    coordinate-H3 mismatch).
    """

    error_code = "VALIDATION_ERROR"


class UCIDContextError(UCIDError):
    """Raised when context computation fails.

    This error indicates a problem during the computation of a
    context score, such as missing data or algorithm failure.
    """

    error_code = "CONTEXT_ERROR"


class UCIDDataError(UCIDError):
    """Raised when required data is missing or invalid.

    This error indicates that external data (OSM, GTFS, etc.) could
    not be loaded or is in an unexpected format.
    """

    error_code = "DATA_ERROR"


class UCIDConfigError(UCIDError):
    """Raised when configuration is invalid.

    This error indicates that the provided configuration does not
    meet the required schema or constraints.
    """

    error_code = "CONFIG_ERROR"


class UCIDRegistryError(UCIDError):
    """Raised when an item cannot be found in a registry.

    This error indicates that a requested item (city, context, etc.)
    is not registered.
    """

    error_code = "REGISTRY_ERROR"
