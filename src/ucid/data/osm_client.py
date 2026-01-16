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

"""OpenStreetMap Overpass API client for UCID.

This module provides an async HTTP client for querying the Overpass API
to fetch real POI (Point of Interest) data for context scoring.

Example:
    >>> from ucid.data.osm_client import OSMClient
    >>> async with OSMClient() as client:
    ...     pois = await client.query_amenities(40.4093, 49.8671, radius=1000)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Overpass API endpoints
OVERPASS_ENDPOINTS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
    "https://maps.mail.ru/osm/tools/overpass/api/interpreter",
]

# POI categories for 15-minute city analysis
POI_CATEGORIES = {
    "grocery": ["supermarket", "convenience", "greengrocer", "bakery", "butcher"],
    "healthcare": ["hospital", "clinic", "doctors", "pharmacy", "dentist"],
    "education": ["school", "kindergarten", "university", "college", "library"],
    "recreation": ["park", "playground", "sports_centre", "swimming_pool", "fitness_centre"],
    "food": ["restaurant", "cafe", "fast_food", "bar", "pub"],
    "transport": ["bus_stop", "subway_entrance", "tram_stop", "train_station", "ferry_terminal"],
    "finance": ["bank", "atm"],
    "childcare": ["childcare", "kindergarten"],
}

# Cache directory
CACHE_DIR = Path.home() / ".ucid" / "cache" / "osm"


class OSMError(Exception):
    """Base exception for OSM client errors."""

    pass


class OSMRateLimitError(OSMError):
    """Raised when rate limit is exceeded."""

    pass


class OSMClient:
    """Async client for OpenStreetMap Overpass API.

    This client provides methods to query POI data from OpenStreetMap
    with automatic rate limiting, caching, and failover between endpoints.

    Attributes:
        timeout: Request timeout in seconds.
        cache_ttl: Cache time-to-live in seconds.
        max_retries: Maximum retry attempts.

    Example:
        >>> async with OSMClient() as client:
        ...     pois = await client.query_amenities(40.4093, 49.8671)
        ...     print(f"Found {len(pois)} POIs")
    """

    def __init__(
        self,
        timeout: float = 30.0,
        cache_ttl: int = 86400,  # 24 hours
        max_retries: int = 3,
        use_cache: bool = True,
    ) -> None:
        """Initialize OSM client.

        Args:
            timeout: Request timeout in seconds.
            cache_ttl: Cache TTL in seconds.
            max_retries: Maximum retry attempts.
            use_cache: Whether to use local caching.
        """
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.max_retries = max_retries
        self.use_cache = use_cache
        self._client: httpx.AsyncClient | None = None
        self._endpoint_index = 0
        self._last_request_time = 0.0
        self._min_request_interval = 1.0  # 1 second between requests

        # Ensure cache directory exists
        if use_cache:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)

    async def __aenter__(self) -> "OSMClient":
        """Enter async context."""
        self._client = httpx.AsyncClient(timeout=self.timeout)
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_cache_key(self, query: str) -> str:
        """Generate cache key from query."""
        return hashlib.sha256(query.encode()).hexdigest()[:16]

    def _get_cache_path(self, cache_key: str) -> Path:
        """Get cache file path."""
        return CACHE_DIR / f"{cache_key}.json"

    def _read_cache(self, cache_key: str) -> dict | None:
        """Read from cache if valid."""
        if not self.use_cache:
            return None

        cache_path = self._get_cache_path(cache_key)
        if not cache_path.exists():
            return None

        try:
            with open(cache_path) as f:
                data = json.load(f)

            # Check TTL
            if time.time() - data.get("timestamp", 0) > self.cache_ttl:
                cache_path.unlink(missing_ok=True)
                return None

            return data.get("result")
        except (json.JSONDecodeError, OSError):
            return None

    def _write_cache(self, cache_key: str, result: dict) -> None:
        """Write result to cache."""
        if not self.use_cache:
            return

        cache_path = self._get_cache_path(cache_key)
        try:
            with open(cache_path, "w") as f:
                json.dump({"timestamp": time.time(), "result": result}, f)
        except OSError as e:
            logger.warning(f"Failed to write cache: {e}")

    async def _rate_limit(self) -> None:
        """Enforce rate limiting."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._min_request_interval:
            await asyncio.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

    async def _execute_query(self, query: str) -> dict:
        """Execute Overpass query with retries and failover."""
        if not self._client:
            raise OSMError("Client not initialized. Use 'async with' context.")

        # Check cache first
        cache_key = self._get_cache_key(query)
        cached = self._read_cache(cache_key)
        if cached is not None:
            logger.debug(f"Cache hit for {cache_key}")
            return cached

        # Rate limiting
        await self._rate_limit()

        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            endpoint = OVERPASS_ENDPOINTS[self._endpoint_index % len(OVERPASS_ENDPOINTS)]

            try:
                logger.debug(f"Query attempt {attempt + 1} to {endpoint}")
                response = await self._client.post(
                    endpoint,
                    data={"data": query},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code == 429:
                    # Rate limited, try next endpoint
                    self._endpoint_index += 1
                    await asyncio.sleep(2 ** attempt)
                    continue

                response.raise_for_status()
                result = response.json()

                # Cache successful result
                self._write_cache(cache_key, result)

                return result

            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code == 429:
                    self._endpoint_index += 1
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise OSMError(f"HTTP error: {e}") from e

            except httpx.RequestError as e:
                last_error = e
                self._endpoint_index += 1
                await asyncio.sleep(2 ** attempt)

        raise OSMError(f"All retries failed: {last_error}")

    def _build_amenity_query(
        self,
        lat: float,
        lon: float,
        radius: int,
        amenity_types: list[str],
    ) -> str:
        """Build Overpass query for amenities.

        Args:
            lat: Center latitude.
            lon: Center longitude.
            radius: Search radius in meters.
            amenity_types: List of amenity types to query.

        Returns:
            Overpass QL query string.
        """
        amenity_filter = "|".join(amenity_types)
        query = f"""
        [out:json][timeout:25];
        (
          node["amenity"~"{amenity_filter}"](around:{radius},{lat},{lon});
          way["amenity"~"{amenity_filter}"](around:{radius},{lat},{lon});
        );
        out center;
        """
        return query.strip()

    async def query_amenities(
        self,
        lat: float,
        lon: float,
        radius: int = 1000,
        categories: list[str] | None = None,
    ) -> list[dict]:
        """Query amenities around a location.

        Args:
            lat: Center latitude.
            lon: Center longitude.
            radius: Search radius in meters.
            categories: POI categories to query. If None, queries all.

        Returns:
            List of POI dictionaries with lat, lon, type, and tags.

        Example:
            >>> pois = await client.query_amenities(40.4093, 49.8671, radius=1000)
            >>> for poi in pois[:3]:
            ...     print(f"{poi['type']}: {poi.get('name', 'unnamed')}")
        """
        if categories is None:
            categories = list(POI_CATEGORIES.keys())

        # Collect all amenity types
        amenity_types: list[str] = []
        for category in categories:
            if category in POI_CATEGORIES:
                amenity_types.extend(POI_CATEGORIES[category])

        if not amenity_types:
            return []

        query = self._build_amenity_query(lat, lon, radius, amenity_types)
        result = await self._execute_query(query)

        pois: list[dict] = []
        for element in result.get("elements", []):
            poi = self._parse_element(element)
            if poi:
                pois.append(poi)

        logger.info(f"Found {len(pois)} POIs at ({lat}, {lon}) within {radius}m")
        return pois

    def _parse_element(self, element: dict) -> dict | None:
        """Parse OSM element to POI dictionary."""
        if element.get("type") == "node":
            lat = element.get("lat")
            lon = element.get("lon")
        elif element.get("type") == "way":
            center = element.get("center", {})
            lat = center.get("lat")
            lon = center.get("lon")
        else:
            return None

        if lat is None or lon is None:
            return None

        tags = element.get("tags", {})
        return {
            "id": element.get("id"),
            "lat": lat,
            "lon": lon,
            "type": tags.get("amenity", "unknown"),
            "name": tags.get("name"),
            "tags": tags,
        }

    async def query_transit_stops(
        self,
        lat: float,
        lon: float,
        radius: int = 1000,
    ) -> list[dict]:
        """Query public transit stops around a location.

        Args:
            lat: Center latitude.
            lon: Center longitude.
            radius: Search radius in meters.

        Returns:
            List of transit stop dictionaries.
        """
        query = f"""
        [out:json][timeout:25];
        (
          node["public_transport"="stop_position"](around:{radius},{lat},{lon});
          node["public_transport"="platform"](around:{radius},{lat},{lon});
          node["highway"="bus_stop"](around:{radius},{lat},{lon});
          node["railway"="tram_stop"](around:{radius},{lat},{lon});
          node["railway"="station"](around:{radius},{lat},{lon});
          node["station"="subway"](around:{radius},{lat},{lon});
        );
        out;
        """

        result = await self._execute_query(query.strip())

        stops: list[dict] = []
        for element in result.get("elements", []):
            if element.get("type") != "node":
                continue

            tags = element.get("tags", {})
            stop_type = (
                tags.get("public_transport")
                or tags.get("railway")
                or tags.get("highway")
                or "transit_stop"
            )

            stops.append({
                "id": element.get("id"),
                "lat": element.get("lat"),
                "lon": element.get("lon"),
                "type": stop_type,
                "name": tags.get("name"),
                "route_ref": tags.get("route_ref"),
                "tags": tags,
            })

        logger.info(f"Found {len(stops)} transit stops at ({lat}, {lon})")
        return stops

    async def query_pedestrian_infrastructure(
        self,
        lat: float,
        lon: float,
        radius: int = 500,
    ) -> dict:
        """Query pedestrian infrastructure for walkability scoring.

        Args:
            lat: Center latitude.
            lon: Center longitude.
            radius: Search radius in meters.

        Returns:
            Dictionary with sidewalks, crossings, and street lights count.
        """
        query = f"""
        [out:json][timeout:25];
        (
          way["highway"="footway"](around:{radius},{lat},{lon});
          way["footway"="sidewalk"](around:{radius},{lat},{lon});
          way["sidewalk"~"both|left|right"](around:{radius},{lat},{lon});
          node["highway"="crossing"](around:{radius},{lat},{lon});
          node["highway"="street_lamp"](around:{radius},{lat},{lon});
        );
        out count;
        """

        result = await self._execute_query(query.strip())

        # Parse counts
        tags = result.get("elements", [{}])[0].get("tags", {})

        return {
            "total_elements": int(tags.get("total", 0)),
            "ways": int(tags.get("ways", 0)),
            "nodes": int(tags.get("nodes", 0)),
        }


async def fetch_pois_for_city(
    city_lat: float,
    city_lon: float,
    grid_size: int = 5,
    cell_radius: int = 500,
) -> dict[str, list[dict]]:
    """Fetch POIs for a city using a grid of queries.

    Args:
        city_lat: City center latitude.
        city_lon: City center longitude.
        grid_size: Grid dimension (grid_size x grid_size queries).
        cell_radius: Radius for each cell query.

    Returns:
        Dictionary mapping categories to POI lists.
    """
    all_pois: dict[str, list[dict]] = {cat: [] for cat in POI_CATEGORIES}

    async with OSMClient() as client:
        # Create grid of query points
        offset = cell_radius / 111000  # Approximate meters to degrees

        for i in range(grid_size):
            for j in range(grid_size):
                lat = city_lat + (i - grid_size // 2) * offset
                lon = city_lon + (j - grid_size // 2) * offset

                try:
                    pois = await client.query_amenities(lat, lon, radius=cell_radius)

                    # Categorize POIs
                    for poi in pois:
                        poi_type = poi.get("type", "")
                        for category, types in POI_CATEGORIES.items():
                            if poi_type in types:
                                all_pois[category].append(poi)
                                break

                except OSMError as e:
                    logger.warning(f"Query failed at ({lat}, {lon}): {e}")

    # Deduplicate by ID
    for category in all_pois:
        seen_ids: set[int] = set()
        unique_pois: list[dict] = []
        for poi in all_pois[category]:
            if poi["id"] not in seen_ids:
                seen_ids.add(poi["id"])
                unique_pois.append(poi)
        all_pois[category] = unique_pois

    return all_pois
