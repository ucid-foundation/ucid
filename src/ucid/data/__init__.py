# Copyright 2024-2026 UCID Foundation
# SPDX-License-Identifier: EUPL-1.2
"""
UCID Data Module.

This module provides access to city registries, context definitions,
and other static data used by the UCID library.

Submodules:
    cities: City registry with 451 global cities across 20 countries.

Example:
    >>> from ucid.data import get_city, list_cities, search_cities
    >>> city = get_city("Baku")
    >>> print(f"{city['name']}: {city['lat']}, {city['lon']}")
    Baku: 40.4093, 49.8671

Author: UCID Foundation
License: EUPL-1.2
"""

from ucid.data.cities import (
    get_azerbaijan_cities,
    get_cities_by_coordinates,
    get_city,
    get_country_info,
    get_registry_info,
    list_cities,
    list_countries,
    search_cities,
)

__all__ = [
    # Registry info
    "get_registry_info",
    # Countries
    "list_countries",
    "get_country_info",
    # Cities
    "list_cities",
    "get_city",
    "search_cities",
    "get_cities_by_coordinates",
    # Azerbaijan-specific
    "get_azerbaijan_cities",
]
