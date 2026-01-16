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

"""UCID-V1: Urban Context Identifier.

A standardized, temporal identifier system and Python library for
comprehensive urban context analysis. UCID provides a universal key for
joining disparate urban datasets across global cities.

Example usage:
    >>> from ucid import create_ucid, parse_ucid
    >>> ucid = create_ucid(city="IST", lat=41.015, lon=28.979,
    ...                    timestamp="2026W01T12", context="15MIN")
    >>> print(ucid)
    UCID-V1:IST:+41.015:+28.979:9:...

For more information, see https://www.ucid.org
"""

__version__ = "1.0.5"
__author__ = "UCID Foundation"
__email__ = "contact@ucid.org"
__url__ = "https://www.ucid.org"

from ucid.core.errors import UCIDError, UCIDParseError, UCIDValidationError
from ucid.core.models import UCID, City
from ucid.core.parser import canonicalize, create_ucid, parse_ucid
from ucid.data import (
    get_azerbaijan_cities,
    get_cities_by_coordinates,
    get_city,
    get_registry_info,
    list_cities,
    list_countries,
    search_cities,
)

__all__ = [
    "__version__",
    # Core functions
    "create_ucid",
    "parse_ucid",
    "canonicalize",
    # Models
    "UCID",
    "City",
    # Errors
    "UCIDError",
    "UCIDParseError",
    "UCIDValidationError",
    # City registry (405 cities, 23 countries)
    "get_registry_info",
    "list_countries",
    "list_cities",
    "get_city",
    "search_cities",
    "get_cities_by_coordinates",
    "get_azerbaijan_cities",
]
