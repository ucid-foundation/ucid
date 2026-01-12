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

"""API error codes and error handling utilities.

This module defines standardized error codes for the UCID API,
enabling consistent error responses across all endpoints.
"""

from enum import Enum


class ErrorCode(str, Enum):
    """Standardized API error codes.

    These error codes are returned in error responses to help
    clients identify and handle specific error conditions.

    Attributes:
        INVALID_UCID: The provided UCID string is malformed.
        MISSING_FIELD: A required field is missing from the request.
        INVALID_COORDINATES: Latitude or longitude is out of range.
        INVALID_CONTEXT: The specified context type is not recognized.
        RATE_LIMITED: Too many requests, rate limit exceeded.
        INTERNAL_ERROR: An unexpected internal error occurred.

    Example:
        >>> from ucid.api.errors import ErrorCode
        >>> error_response = {"code": ErrorCode.INVALID_UCID, "message": "..."}
    """

    INVALID_UCID = "invalid_ucid"
    MISSING_FIELD = "missing_field"
    INVALID_COORDINATES = "invalid_coordinates"
    INVALID_CONTEXT = "invalid_context"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"
