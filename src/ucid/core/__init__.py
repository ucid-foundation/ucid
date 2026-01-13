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

"""UCID Core module.

This module provides the core functionality for UCID parsing, validation,
and creation. It exports the primary APIs for working with Urban Context
Identifiers.

Example:
    >>> from ucid.core import create_ucid, parse_ucid, UCID
    >>> ucid = create_ucid(city="IST", lat=41.015, lon=28.979,
    ...                    timestamp="2026W01T12", context="15MIN")
"""

from ucid.core.constants import (
    BUILTIN_CONTEXTS,
    DEFAULT_H3_RESOLUTION,
    GRADE_THRESHOLDS,
    UCID_VERSION_PREFIX,
    VALID_GRADES,
)
from ucid.core.errors import (
    UCIDConfigError,
    UCIDContextError,
    UCIDDataError,
    UCIDError,
    UCIDParseError,
    UCIDRegistryError,
    UCIDValidationError,
)
from ucid.core.models import UCID, City
from ucid.core.parser import canonicalize, create_ucid, parse_ucid
from ucid.core.registry import CityRegistry
from ucid.core.validator import validate_ucid

__all__ = [
    # Models
    "UCID",
    "City",
    # Parser functions
    "create_ucid",
    "parse_ucid",
    "canonicalize",
    # Validation
    "validate_ucid",
    "CityRegistry",
    # Exceptions
    "UCIDError",
    "UCIDParseError",
    "UCIDValidationError",
    "UCIDContextError",
    "UCIDDataError",
    "UCIDConfigError",
    "UCIDRegistryError",
    # Constants
    "UCID_VERSION_PREFIX",
    "DEFAULT_H3_RESOLUTION",
    "VALID_GRADES",
    "GRADE_THRESHOLDS",
    "BUILTIN_CONTEXTS",
]
