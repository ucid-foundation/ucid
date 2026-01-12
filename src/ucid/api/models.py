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

"""API request and response models.

This module defines Pydantic models for API request validation
and response serialization, ensuring type safety and documentation.
"""

from typing import Any

from pydantic import BaseModel, Field


class ParseRequest(BaseModel):
    """Request model for parsing a UCID string.

    Attributes:
        ucid_string: The UCID string to parse.
        strict: Whether to perform strict validation. Defaults to True.
    """

    ucid_string: str = Field(..., description="UCID string to parse")
    strict: bool = Field(default=True, description="Enable strict validation")


class ScoreRequest(BaseModel):
    """Request model for context scoring.

    Attributes:
        lat: Latitude in decimal degrees (-90 to 90).
        lon: Longitude in decimal degrees (-180 to 180).
        context: Context identifier (e.g., 15MIN, TRANSIT).
        timestamp: Optional ISO week timestamp.
        config: Optional configuration parameters.
    """

    lat: float = Field(..., ge=-90, le=90, description="Latitude")
    lon: float = Field(..., ge=-180, le=180, description="Longitude")
    context: str = Field(..., description="Context identifier")
    timestamp: str | None = Field(default=None, description="ISO week timestamp")
    config: dict[str, Any] | None = Field(
        default=None,
        description="Optional configuration",
    )


class ErrorResponse(BaseModel):
    """Standard error response model.

    Attributes:
        code: Machine-readable error code.
        message: Human-readable error message.
        details: Optional additional error details.
    """

    code: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    details: dict[str, Any] | None = Field(
        default=None,
        description="Additional details",
    )
