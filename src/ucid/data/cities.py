# Copyright 2024-2026 UCID Foundation
# SPDX-License-Identifier: EUPL-1.2
"""
City Registry Module for UCID.

This module provides access to the global cities registry containing
451 cities across 20 countries with coordinates, timezones, and metadata.

Author: UCID Foundation
License: EUPL-1.2

Example:
    >>> from ucid.data import get_city, list_cities, search_cities
    >>> city = get_city("Baku")
    >>> print(city["lat"], city["lon"])
    40.4093 49.8671
    >>> cities = list_cities(country="Azerbaijan")
    >>> print(len(cities))
    10
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Load cities registry
_REGISTRY_PATH = Path(__file__).parent / "cities_registry.json"
_REGISTRY: dict[str, Any] | None = None


def _load_registry() -> dict[str, Any]:
    """Load the cities registry from JSON file."""
    global _REGISTRY
    if _REGISTRY is None:
        with open(_REGISTRY_PATH, encoding="utf-8") as f:
            _REGISTRY = json.load(f)
    return _REGISTRY


def get_registry_info() -> dict[str, Any]:
    """
    Get registry metadata.

    Returns:
        Dictionary with version, last_updated, total_cities, and countries count.

    Example:
        >>> info = get_registry_info()
        >>> print(f"Version: {info['version']}, Cities: {info['total_cities']}")
        Version: 1.0.5, Cities: 451
    """
    registry = _load_registry()
    return {
        "version": registry.get("version", "unknown"),
        "last_updated": registry.get("last_updated", "unknown"),
        "total_cities": registry.get("total_cities", 0),
        "countries": registry.get("countries", 0)
    }


def list_countries() -> list[str]:
    """
    List all available countries in the registry.

    Returns:
        List of country names (lowercase keys).

    Example:
        >>> countries = list_countries()
        >>> print("azerbaijan" in countries)
        True
    """
    registry = _load_registry()
    return list(registry.get("cities", {}).keys())


def get_country_info(country: str) -> dict[str, Any] | None:
    """
    Get country metadata including timezone and country code.

    Args:
        country: Country name (case-insensitive).

    Returns:
        Dictionary with country_code, timezone, and city count, or None if not found.

    Example:
        >>> info = get_country_info("Azerbaijan")
        >>> print(info["country_code"])
        AZ
    """
    registry = _load_registry()
    country_key = country.lower().replace(" ", "_")
    country_data = registry.get("cities", {}).get(country_key)

    if country_data is None:
        return None

    return {
        "country_code": country_data.get("country_code"),
        "timezone": country_data.get("timezone"),
        "languages": country_data.get("languages", []),
        "city_count": len(country_data.get("cities", []))
    }


def list_cities(
    country: str | None = None,
    min_population: int | None = None
) -> list[dict[str, Any]]:
    """
    List cities, optionally filtered by country or minimum population.

    Args:
        country: Filter by country name (case-insensitive).
        min_population: Minimum population threshold.

    Returns:
        List of city dictionaries with name, lat, lon, population.

    Example:
        >>> cities = list_cities(country="Azerbaijan")
        >>> print(len(cities))
        10
        >>> large_cities = list_cities(min_population=1000000)
        >>> print(len(large_cities) > 50)
        True
    """
    registry = _load_registry()
    cities_data = registry.get("cities", {})

    result = []

    for country_key, country_info in cities_data.items():
        if country and country_key != country.lower().replace(" ", "_"):
            continue

        for city in country_info.get("cities", []):
            if min_population and city.get("population", 0) < min_population:
                continue

            result.append({
                "name": city.get("name"),
                "name_local": city.get("name_local"),
                "name_en": city.get("name_en"),
                "lat": city.get("lat"),
                "lon": city.get("lon"),
                "population": city.get("population", 0),
                "country": country_key,
                "country_code": country_info.get("country_code"),
                "timezone": country_info.get("timezone")
            })

    return result


def get_city(
    name: str,
    country: str | None = None
) -> dict[str, Any] | None:
    """
    Get a specific city by name.

    Args:
        name: City name (case-insensitive, matches name, name_local, or name_en).
        country: Optional country filter for disambiguation.

    Returns:
        City dictionary with all metadata, or None if not found.

    Example:
        >>> city = get_city("Baku")
        >>> print(f"{city['name']}: {city['lat']}, {city['lon']}")
        Baku: 40.4093, 49.8671

        >>> city = get_city("Vienna", country="Austria")
        >>> print(city["population"])
        1911191
    """
    registry = _load_registry()
    cities_data = registry.get("cities", {})
    name_lower = name.lower()

    for country_key, country_info in cities_data.items():
        if country and country_key != country.lower().replace(" ", "_"):
            continue

        for city in country_info.get("cities", []):
            city_name = city.get("name", "").lower()
            city_local = city.get("name_local", "").lower()
            city_en = city.get("name_en", "").lower()

            if name_lower in (city_name, city_local, city_en):
                return {
                    "name": city.get("name"),
                    "name_local": city.get("name_local"),
                    "name_en": city.get("name_en"),
                    "lat": city.get("lat"),
                    "lon": city.get("lon"),
                    "population": city.get("population", 0),
                    "priority": city.get("priority"),
                    "country": country_key,
                    "country_code": country_info.get("country_code"),
                    "timezone": country_info.get("timezone")
                }

    return None


def search_cities(
    query: str,
    limit: int = 10
) -> list[dict[str, Any]]:
    """
    Search cities by partial name match.

    Args:
        query: Search query (case-insensitive, partial match).
        limit: Maximum number of results to return.

    Returns:
        List of matching city dictionaries, sorted by population descending.

    Example:
        >>> results = search_cities("Istan")
        >>> print(results[0]["name"])
        Istanbul

        >>> results = search_cities("bak", limit=5)
        >>> print(any(c["name"] == "Baku" for c in results))
        True
    """
    registry = _load_registry()
    cities_data = registry.get("cities", {})
    query_lower = query.lower()

    matches = []

    for country_key, country_info in cities_data.items():
        for city in country_info.get("cities", []):
            city_name = city.get("name", "").lower()
            city_local = city.get("name_local", "").lower()
            city_en = city.get("name_en", "").lower()

            if (query_lower in city_name or
                query_lower in city_local or
                query_lower in city_en):
                matches.append({
                    "name": city.get("name"),
                    "name_local": city.get("name_local"),
                    "name_en": city.get("name_en"),
                    "lat": city.get("lat"),
                    "lon": city.get("lon"),
                    "population": city.get("population", 0),
                    "country": country_key,
                    "country_code": country_info.get("country_code"),
                    "timezone": country_info.get("timezone")
                })

    # Sort by population descending
    matches.sort(key=lambda x: x.get("population", 0), reverse=True)

    return matches[:limit]


def get_cities_by_coordinates(
    lat: float,
    lon: float,
    radius_km: float = 50.0
) -> list[dict[str, Any]]:
    """
    Find cities within a radius of given coordinates.

    Uses Haversine formula for distance calculation.

    Args:
        lat: Latitude in degrees.
        lon: Longitude in degrees.
        radius_km: Search radius in kilometers.

    Returns:
        List of cities within the radius, sorted by distance ascending.

    Example:
        >>> # Find cities near Baku
        >>> cities = get_cities_by_coordinates(40.4, 49.8, radius_km=100)
        >>> print(cities[0]["name"])
        Baku
    """
    import math

    def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance in km between two coordinates."""
        R = 6371  # Earth radius in km
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        return R * 2 * math.asin(math.sqrt(a))

    registry = _load_registry()
    cities_data = registry.get("cities", {})

    matches = []

    for country_key, country_info in cities_data.items():
        for city in country_info.get("cities", []):
            city_lat = city.get("lat", 0)
            city_lon = city.get("lon", 0)
            distance = haversine(lat, lon, city_lat, city_lon)

            if distance <= radius_km:
                matches.append({
                    "name": city.get("name"),
                    "lat": city_lat,
                    "lon": city_lon,
                    "population": city.get("population", 0),
                    "country": country_key,
                    "distance_km": round(distance, 2)
                })

    # Sort by distance ascending
    matches.sort(key=lambda x: x.get("distance_km", float("inf")))

    return matches


def get_azerbaijan_cities() -> list[dict[str, Any]]:
    """
    Get all Azerbaijani cities with full metadata.

    Returns priority cities first (Baku, Sumqayit, Ganja).

    Returns:
        List of Azerbaijani city dictionaries.

    Example:
        >>> cities = get_azerbaijan_cities()
        >>> print(cities[0]["name"])
        Baku
        >>> print(len(cities))
        10
    """
    cities = list_cities(country="azerbaijan")

    # Sort by priority and population
    def sort_key(city: dict[str, Any]) -> tuple[int, int]:
        priority_order = {"primary": 0, "high": 1}
        priority = priority_order.get(city.get("priority", ""), 2)
        return (priority, -city.get("population", 0))

    cities.sort(key=sort_key)
    return cities


# Module exports
__all__ = [
    "get_registry_info",
    "list_countries",
    "get_country_info",
    "list_cities",
    "get_city",
    "search_cities",
    "get_cities_by_coordinates",
    "get_azerbaijan_cities",
]
