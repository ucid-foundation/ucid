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

"""Input validation helpers for UCID.

This module provides common validation functions used across the library.
"""

import re


def validate_coordinates(lat: float, lon: float) -> tuple[bool, str]:
    """Validate geographic coordinates.

    Args:
        lat: Latitude value.
        lon: Longitude value.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> valid, msg = validate_coordinates(41.015, 28.979)
        >>> print(valid)
        True
    """
    if not -90.0 <= lat <= 90.0:
        return False, f"Latitude {lat} out of range [-90, 90]"

    if not -180.0 <= lon <= 180.0:
        return False, f"Longitude {lon} out of range [-180, 180]"

    return True, ""


def validate_city_code(code: str) -> tuple[bool, str]:
    """Validate a city code format.

    Args:
        code: City code to validate.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> valid, msg = validate_city_code("IST")
        >>> print(valid)
        True
    """
    if not code:
        return False, "City code cannot be empty"

    if len(code) != 3:
        return False, f"City code must be 3 characters, got {len(code)}"

    if not code.isupper() or not code.isalpha():
        return False, "City code must be 3 uppercase letters"

    return True, ""


def validate_timestamp(timestamp: str) -> tuple[bool, str]:
    """Validate a temporal key format.

    Args:
        timestamp: Timestamp string (YYYYWwwThh format).

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> valid, msg = validate_timestamp("2026W01T12")
        >>> print(valid)
        True
    """
    pattern = r"^\d{4}W(?:0[1-9]|[1-4]\d|5[0-3])T(?:0\d|1\d|2[0-3])$"

    if not re.match(pattern, timestamp):
        return False, f"Invalid timestamp format: {timestamp}. Expected YYYYWwwThh"

    return True, ""


def validate_grade(grade: str) -> tuple[bool, str]:
    """Validate a grade value.

    Args:
        grade: Grade string.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> valid, msg = validate_grade("A")
        >>> print(valid)
        True
    """
    valid_grades = {"A+", "A", "B", "C", "D", "F"}

    if grade not in valid_grades:
        return False, f"Invalid grade: {grade}. Must be one of {valid_grades}"

    return True, ""
