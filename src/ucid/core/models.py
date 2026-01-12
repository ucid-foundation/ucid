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

"""Pydantic models for UCID data structures.

This module defines the core data models used throughout UCID, including
the UCID identifier itself, City definitions, and TemporalKey representations.
All models use Pydantic for runtime validation and serialization.

Example:
    >>> from ucid.core.models import UCID, City
    >>> city = City(code="IST", full_name="Istanbul", country="TR",
    ...             timezone="Europe/Istanbul")
    >>> print(city.code)
    IST
"""

import pytz
from pydantic import BaseModel, Field, field_validator, model_validator

from ucid.core.constants import (
    MAX_LAT,
    MAX_LON,
    MIN_LAT,
    MIN_LON,
    UCID_CURRENT_VERSION,
    VALID_GRADES,
)


class City(BaseModel):
    """City definition for the UCID registry.

    Attributes:
        code: 3-character uppercase city code (e.g., "IST", "NYC").
        full_name: Full display name of the city.
        country: 2-character ISO country code.
        timezone: IANA timezone identifier.
        population: Optional population estimate.
        bbox: Optional bounding box as (min_lat, min_lon, max_lat, max_lon).
    """

    code: str = Field(
        ...,
        min_length=3,
        max_length=3,
        pattern=r"^[A-Z]{3}$",
        description="3-character uppercase city code",
    )
    full_name: str = Field(..., description="Full display name")
    country: str = Field(
        ...,
        min_length=2,
        max_length=2,
        description="ISO 3166-1 alpha-2 country code",
    )
    timezone: str = Field(..., description="IANA timezone identifier")
    population: int | None = Field(default=None, ge=0)
    bbox: tuple[float, float, float, float] | None = Field(
        default=None,
        description="Bounding box: (min_lat, min_lon, max_lat, max_lon)",
    )

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, v: str) -> str:
        """Validate that timezone is a valid IANA timezone."""
        if v not in pytz.all_timezones_set:
            raise ValueError(f"Unknown timezone: {v}")
        return v

    model_config = {"frozen": True}


class UCID(BaseModel):
    """Urban Context Identifier model.

    Format: UCID-V1:{CITY}:{LAT3}:{LON3}:{H3R}:{H3}:{TIME}:{CONTEXT}:{GRADE}:{CONF}:{FLAGS}

    Attributes:
        version: UCID format version (e.g., "V1").
        city: 3-character city code.
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        h3_res: H3 resolution level (0-15).
        h3_index: H3 cell index as hexadecimal string.
        timestamp: Temporal key in ISO week format (YYYYWwwThh).
        context: Context identifier (e.g., "15MIN").
        grade: Quality grade (A+, A, B, C, D, F).
        confidence: Confidence score (0.0 to 1.0).
        flags: Optional list of flags (e.g., ["APPROX", "CACHED"]).
    """

    version: str = Field(default=UCID_CURRENT_VERSION, pattern=r"^V[0-9]+$")
    city: str = Field(..., min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    lat: float = Field(..., ge=MIN_LAT, le=MAX_LAT)
    lon: float = Field(..., ge=MIN_LON, le=MAX_LON)
    h3_res: int = Field(..., ge=0, le=15)
    h3_index: str = Field(..., pattern=r"^[0-9a-f]{15}$")
    timestamp: str = Field(..., pattern=r"^\d{4}W\d{2}T\d{2}$")
    context: str = Field(..., pattern=r"^[A-Z0-9]+$", max_length=8)
    grade: str = Field(...)
    confidence: float = Field(..., ge=0.0, le=1.0)
    flags: list[str] = Field(default_factory=list)

    @property
    def lat3(self) -> str:
        """Format latitude to 3 decimal places with sign."""
        return f"{self.lat:+.3f}"

    @property
    def lon3(self) -> str:
        """Format longitude to 3 decimal places with sign."""
        return f"{self.lon:+.3f}"

    @property
    def conf2(self) -> str:
        """Format confidence to 2 decimal places."""
        return f"{self.confidence:.2f}"

    @property
    def flags_str(self) -> str:
        """Join flags with semicolon separator."""
        return ";".join(sorted(self.flags))

    def to_canonical_string(self) -> str:
        """Generate the canonical UCID string representation.

        Returns:
            Canonical UCID string in the format:
            UCID-V1:{CITY}:{LAT3}:{LON3}:{H3R}:{H3}:{TIME}:{CONTEXT}:{GRADE}:{CONF}:{FLAGS}
        """
        prefix = f"UCID-{self.version}"
        return (
            f"{prefix}:{self.city}:{self.lat3}:{self.lon3}:{self.h3_res}:"
            f"{self.h3_index}:{self.timestamp}:{self.context}:{self.grade}:"
            f"{self.conf2}:{self.flags_str}"
        )

    def __str__(self) -> str:
        """Return canonical string representation."""
        return self.to_canonical_string()

    @field_validator("grade")
    @classmethod
    def validate_grade(cls, v: str) -> str:
        """Validate grade is in the allowed set."""
        if v not in VALID_GRADES:
            raise ValueError(f"Invalid grade: {v}. Must be one of {VALID_GRADES}")
        return v

    @model_validator(mode="after")
    def validate_h3_consistency(self) -> "UCID":
        """Validate H3 index is consistent with coordinates.

        Note: Full H3 validation requires the h3 library and is performed
        in the validator module for strict mode.
        """
        return self

    model_config = {"frozen": True}
