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

"""Validation logic for UCID objects.

This module provides functions to validate UCID objects against semantic
rules, including city registry lookup and H3 spatial consistency checks.

Example:
    >>> from ucid.core.validator import validate_ucid
    >>> ucid = parse_ucid("UCID-V1:IST:+41.015:+28.979:...")
    >>> errors = validate_ucid(ucid, strict=True)
"""

import h3

from ucid.core.errors import UCIDValidationError
from ucid.core.models import UCID
from ucid.core.registry import CityRegistry


def validate_h3_match(
    lat: float,
    lon: float,
    h3_index: str,
    h3_res: int,
) -> bool:
    """Validate that lat/lon coordinates match the given H3 index.

    Args:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        h3_index: H3 cell index as hexadecimal string.
        h3_res: H3 resolution level.

    Returns:
        True if coordinates match the H3 index, False otherwise.
    """
    try:
        # Support h3-py v4 and v3 API
        if hasattr(h3, "latlng_to_cell"):
            computed = h3.latlng_to_cell(lat, lon, h3_res)
        else:
            computed = h3.geo_to_h3(lat, lon, h3_res)

        return computed == h3_index
    except Exception:
        return False


def validate_h3_index(h3_index: str) -> bool:
    """Validate that an H3 index string is valid.

    Args:
        h3_index: H3 cell index as hexadecimal string.

    Returns:
        True if valid H3 index, False otherwise.
    """
    try:
        if hasattr(h3, "is_valid_cell"):
            return h3.is_valid_cell(h3_index)
        if hasattr(h3, "h3_is_valid"):
            return h3.h3_is_valid(h3_index)
        return False
    except Exception:
        return False


def validate_ucid(ucid: UCID, strict: bool = True) -> list[str]:
    """Validate a UCID object against semantic rules.

    This function performs the following validations:
    1. City code exists in the registry
    2. H3 index is a valid H3 cell
    3. H3 index matches the lat/lon coordinates (strict mode only)

    Args:
        ucid: UCID object to validate.
        strict: If True, raise exceptions on validation failure.
                If False, return a list of warning messages.

    Returns:
        List of warning messages (empty if valid in non-strict mode).

    Raises:
        UCIDValidationError: If strict=True and validation fails.

    Example:
        >>> ucid = UCID(city="IST", lat=41.015, ...)
        >>> validate_ucid(ucid, strict=True)  # Raises if invalid
        >>> warnings = validate_ucid(ucid, strict=False)
        >>> print(warnings)
        []
    """
    errors: list[str] = []

    # 1. Validate City Code
    registry = CityRegistry()
    if not registry.exists(ucid.city):
        msg = f"City code '{ucid.city}' not found in registry."
        if strict:
            raise UCIDValidationError(
                msg,
                code="INVALID_CITY",
                details={"city": ucid.city},
            )
        errors.append(msg)

    # 2. Validate H3 Index Format
    if not validate_h3_index(ucid.h3_index):
        msg = f"Invalid H3 index string: {ucid.h3_index}"
        if strict:
            raise UCIDValidationError(
                msg,
                code="INVALID_H3",
                details={"h3_index": ucid.h3_index},
            )
        errors.append(msg)

    # 3. Validate Geo-H3 Consistency (strict mode only)
    if strict and not validate_h3_match(ucid.lat, ucid.lon, ucid.h3_index, ucid.h3_res):
        raise UCIDValidationError(
            f"Coordinates ({ucid.lat}, {ucid.lon}) do not match H3 index {ucid.h3_index} at resolution {ucid.h3_res}",
            code="H3_MISMATCH",
            details={
                "lat": ucid.lat,
                "lon": ucid.lon,
                "h3_index": ucid.h3_index,
                "h3_res": ucid.h3_res,
            },
        )

    return errors
