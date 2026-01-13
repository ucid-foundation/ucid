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

"""UCID parsing and creation functions.

This module provides the primary interface for creating and parsing UCID
identifiers. It includes functions for parsing UCID strings, creating new
UCIDs from coordinates, and canonicalizing UCID representations.

Example:
    >>> from ucid.core.parser import create_ucid, parse_ucid
    >>> ucid = create_ucid(city="IST", lat=41.015, lon=28.979,
    ...                    timestamp="2026W01T12", context="15MIN")
    >>> parsed = parse_ucid(str(ucid))
    >>> print(parsed.city)
    IST
"""

import h3

from ucid.core.constants import DEFAULT_H3_RESOLUTION, UCID_CURRENT_VERSION
from ucid.core.errors import UCIDParseError
from ucid.core.models import UCID
from ucid.core.validator import validate_ucid


def parse_ucid(ucid_string: str, strict: bool = True) -> UCID:
    """Parse a UCID string into a UCID object.

    This function parses a canonical UCID string and returns a validated
    UCID object. The string must conform to the UCID-V1 format specification.

    Args:
        ucid_string: Canonical UCID string to parse.
        strict: If True, validate against semantic rules (city registry,
                H3 consistency). If False, only validate format.

    Returns:
        Parsed and validated UCID object.

    Raises:
        UCIDParseError: If the string format is invalid.
        UCIDValidationError: If strict=True and semantic validation fails.

    Example:
        >>> ucid = parse_ucid("UCID-V1:IST:+41.015:+28.979:9:891f2ed6df7ffff:2026W01T12:15MIN:A:0.95:")
        >>> print(ucid.city)
        IST
    """
    parts = ucid_string.split(":")

    # Validate prefix
    if not parts or not parts[0].startswith("UCID-V"):
        raise UCIDParseError(
            f"Invalid prefix: {parts[0] if parts else 'empty'}. Must start with 'UCID-V'",
            code="INVALID_PREFIX",
        )

    version = parts[0].replace("UCID-", "")

    # Validate field count
    # Fields: Prefix, City, Lat, Lon, H3R, H3, Time, Context, Grade, Conf, Flags
    if len(parts) < 10:
        raise UCIDParseError(
            f"Insufficient number of fields: {len(parts)}. Expected at least 10.",
            code="MALFORMED_STRING",
            details={"field_count": len(parts)},
        )

    try:
        city = parts[1]
        lat = float(parts[2])
        lon = float(parts[3])
        h3_res = int(parts[4])
        h3_index = parts[5]
        timestamp = parts[6]
        context = parts[7]
        grade = parts[8]
        confidence = float(parts[9])

        flags_str = parts[10] if len(parts) > 10 else ""
        flags = [f for f in flags_str.split(";") if f]

        ucid_obj = UCID(
            version=version,
            city=city,
            lat=lat,
            lon=lon,
            h3_res=h3_res,
            h3_index=h3_index,
            timestamp=timestamp,
            context=context,
            grade=grade,
            confidence=confidence,
            flags=flags,
        )

        # Perform semantic validation
        validate_ucid(ucid_obj, strict=strict)

        return ucid_obj

    except ValueError as e:
        raise UCIDParseError(
            f"Field format error: {e!s}",
            code="FIELD_FORMAT",
            details={"error": str(e)},
        ) from e
    except UCIDParseError:
        raise
    except Exception as e:
        raise UCIDParseError(
            f"Unexpected parsing error: {e!s}",
            code="UNKNOWN_ERROR",
            details={"error": str(e)},
        ) from e


def create_ucid(
    city: str,
    lat: float,
    lon: float,
    timestamp: str,
    context: str,
    grade: str = "F",
    confidence: float = 0.0,
    h3_res: int = DEFAULT_H3_RESOLUTION,
    flags: list[str] | None = None,
    h3_index: str | None = None,
) -> UCID:
    """Create a new UCID object from coordinates and metadata.

    This function creates a UCID with automatic H3 index computation if
    not provided. The resulting UCID is validated before being returned.

    Args:
        city: 3-character city code (must be in registry).
        lat: Latitude in decimal degrees (-90 to 90).
        lon: Longitude in decimal degrees (-180 to 180).
        timestamp: Temporal key in ISO week format (YYYYWwwThh).
        context: Context identifier (e.g., "15MIN", "TRANSIT").
        grade: Quality grade. Defaults to "F".
        confidence: Confidence score (0.0 to 1.0). Defaults to 0.0.
        h3_res: H3 resolution level (0-15). Defaults to 9.
        flags: Optional list of flags.
        h3_index: Optional pre-computed H3 index. If None, computed from
                  lat/lon.

    Returns:
        Validated UCID object.

    Example:
        >>> ucid = create_ucid(
        ...     city="IST",
        ...     lat=41.015,
        ...     lon=28.979,
        ...     timestamp="2026W01T12",
        ...     context="15MIN",
        ...     grade="A",
        ...     confidence=0.95
        ... )
        >>> print(ucid)
        UCID-V1:IST:+41.015:+28.979:9:...
    """
    # Compute H3 index if not provided
    if h3_index is None:
        if hasattr(h3, "latlng_to_cell"):
            h3_index = h3.latlng_to_cell(lat, lon, h3_res)
        else:
            h3_index = h3.geo_to_h3(lat, lon, h3_res)

    return UCID(
        version=UCID_CURRENT_VERSION,
        city=city.upper(),
        lat=lat,
        lon=lon,
        h3_res=h3_res,
        h3_index=h3_index,
        timestamp=timestamp,
        context=context.upper(),
        grade=grade,
        confidence=confidence,
        flags=flags or [],
    )


def canonicalize(ucid_string: str) -> str:
    """Parse and re-serialize a UCID string to canonical form.

    This function ensures that a UCID string is in its canonical
    representation, normalizing field formatting and ordering.

    Args:
        ucid_string: UCID string to canonicalize.

    Returns:
        Canonical UCID string.

    Example:
        >>> canonical = canonicalize("UCID-V1:ist:41.015:28.979:...")
        >>> print(canonical)
        UCID-V1:IST:+41.015:+28.979:...
    """
    ucid_obj = parse_ucid(ucid_string, strict=False)
    return ucid_obj.to_canonical_string()
