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

"""POI Fetcher for UCID context scoring.

This module provides high-level functions for fetching and caching
Point of Interest (POI) data from OpenStreetMap for use in context
scoring algorithms.

Example:
    >>> from ucid.data.poi_fetcher import POIFetcher
    >>> fetcher = POIFetcher()
    >>> pois = fetcher.get_pois_for_location(40.4093, 49.8671)
    >>> print(f"Found {pois.total_count} POIs")
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Cache configuration
CACHE_DIR = Path.home() / ".ucid" / "cache" / "pois"
CACHE_DB = CACHE_DIR / "pois.db"
CACHE_TTL_SECONDS = 86400 * 7  # 7 days


@dataclass
class POICollection:
    """Collection of POIs with metadata.

    Attributes:
        pois: List of POI dictionaries.
        categories: Dictionary mapping category names to POI lists.
        total_count: Total number of POIs.
        fetch_time: Unix timestamp of data fetch.
        source: Data source identifier.
    """

    pois: list[dict[str, Any]] = field(default_factory=list)
    categories: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    total_count: int = 0
    fetch_time: float = 0.0
    source: str = "osm-overpass"

    def get_category_count(self, category: str) -> int:
        """Get POI count for a category."""
        return len(self.categories.get(category, []))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "pois": self.pois,
            "categories": {k: v for k, v in self.categories.items()},
            "total_count": self.total_count,
            "fetch_time": self.fetch_time,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "POICollection":
        """Create from dictionary."""
        return cls(
            pois=data.get("pois", []),
            categories=data.get("categories", {}),
            total_count=data.get("total_count", 0),
            fetch_time=data.get("fetch_time", 0.0),
            source=data.get("source", "unknown"),
        )


class POIFetcher:
    """High-level POI fetcher with caching.

    This class provides methods to fetch POI data from OpenStreetMap
    with SQLite-based caching for improved performance.

    Attributes:
        use_cache: Whether to use local caching.
        cache_ttl: Cache TTL in seconds.

    Example:
        >>> fetcher = POIFetcher()
        >>> pois = fetcher.get_pois_for_location(40.4093, 49.8671)
        >>> for cat, items in pois.categories.items():
        ...     print(f"{cat}: {len(items)}")
    """

    def __init__(
        self,
        use_cache: bool = True,
        cache_ttl: int = CACHE_TTL_SECONDS,
    ) -> None:
        """Initialize POI fetcher.

        Args:
            use_cache: Whether to cache results.
            cache_ttl: Cache TTL in seconds.
        """
        self.use_cache = use_cache
        self.cache_ttl = cache_ttl

        if use_cache:
            self._init_cache_db()

    def _init_cache_db(self) -> None:
        """Initialize SQLite cache database."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(CACHE_DB) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS poi_cache (
                    cache_key TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at
                ON poi_cache(created_at)
            """)
            conn.commit()

    def _get_cache_key(self, lat: float, lon: float, radius: int) -> str:
        """Generate cache key."""
        # Round to 3 decimal places for cache grouping
        lat_key = round(lat, 3)
        lon_key = round(lon, 3)
        return f"{lat_key}:{lon_key}:{radius}"

    def _read_cache(self, cache_key: str) -> POICollection | None:
        """Read from cache if valid."""
        if not self.use_cache:
            return None

        try:
            with sqlite3.connect(CACHE_DB) as conn:
                cursor = conn.execute(
                    "SELECT data, created_at FROM poi_cache WHERE cache_key = ?",
                    (cache_key,),
                )
                row = cursor.fetchone()

                if not row:
                    return None

                data_json, created_at = row

                # Check TTL
                if time.time() - created_at > self.cache_ttl:
                    conn.execute(
                        "DELETE FROM poi_cache WHERE cache_key = ?",
                        (cache_key,),
                    )
                    conn.commit()
                    return None

                data = json.loads(data_json)
                return POICollection.from_dict(data)

        except (sqlite3.Error, json.JSONDecodeError) as e:
            logger.warning(f"Cache read error: {e}")
            return None

    def _write_cache(self, cache_key: str, collection: POICollection) -> None:
        """Write to cache."""
        if not self.use_cache:
            return

        try:
            data_json = json.dumps(collection.to_dict())

            with sqlite3.connect(CACHE_DB) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO poi_cache (cache_key, data, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (cache_key, data_json, time.time()),
                )
                conn.commit()

        except (sqlite3.Error, json.JSONEncodeError) as e:
            logger.warning(f"Cache write error: {e}")

    def get_pois_for_location(
        self,
        lat: float,
        lon: float,
        radius: int = 1000,
        categories: list[str] | None = None,
    ) -> POICollection:
        """Get POIs for a location.

        Args:
            lat: Latitude.
            lon: Longitude.
            radius: Search radius in meters.
            categories: Categories to fetch. None for all.

        Returns:
            POICollection with fetched POIs.
        """
        cache_key = self._get_cache_key(lat, lon, radius)

        # Check cache
        cached = self._read_cache(cache_key)
        if cached is not None:
            logger.debug(f"Cache hit for {cache_key}")
            return cached

        # Fetch from OSM
        try:
            collection = asyncio.run(
                self._fetch_async(lat, lon, radius, categories)
            )
        except RuntimeError:
            # Already in async context
            loop = asyncio.get_event_loop()
            collection = loop.run_until_complete(
                self._fetch_async(lat, lon, radius, categories)
            )

        # Write to cache
        self._write_cache(cache_key, collection)

        return collection

    async def _fetch_async(
        self,
        lat: float,
        lon: float,
        radius: int,
        categories: list[str] | None,
    ) -> POICollection:
        """Async fetch from OSM."""
        try:
            from ucid.data.osm_client import OSMClient, POI_CATEGORIES

            async with OSMClient(use_cache=True) as client:
                pois = await client.query_amenities(
                    lat=lat,
                    lon=lon,
                    radius=radius,
                    categories=categories,
                )

            # Categorize POIs
            categorized: dict[str, list[dict[str, Any]]] = {}

            for poi in pois:
                poi_type = poi.get("type", "")
                for cat_name, cat_types in POI_CATEGORIES.items():
                    if poi_type in cat_types:
                        if cat_name not in categorized:
                            categorized[cat_name] = []
                        categorized[cat_name].append(poi)
                        break

            return POICollection(
                pois=pois,
                categories=categorized,
                total_count=len(pois),
                fetch_time=time.time(),
                source="osm-overpass",
            )

        except ImportError:
            logger.error("OSM client not available")
            return POICollection(source="error-no-client")
        except Exception as e:
            logger.error(f"POI fetch failed: {e}")
            return POICollection(source="error")

    def get_pois_for_h3_cell(
        self,
        h3_index: str,
        categories: list[str] | None = None,
    ) -> POICollection:
        """Get POIs for an H3 cell.

        Args:
            h3_index: H3 cell index.
            categories: Categories to fetch.

        Returns:
            POICollection with fetched POIs.
        """
        try:
            import h3

            lat, lon = h3.h3_to_geo(h3_index)
            resolution = h3.h3_get_resolution(h3_index)

            # Approximate cell radius based on resolution
            resolution_radii = {
                7: 2500,
                8: 1000,
                9: 500,
                10: 200,
                11: 100,
            }
            radius = resolution_radii.get(resolution, 500)

            return self.get_pois_for_location(lat, lon, radius, categories)

        except ImportError:
            logger.error("h3 library not available")
            return POICollection(source="error-no-h3")

    def clear_cache(self) -> None:
        """Clear all cached data."""
        if not self.use_cache:
            return

        try:
            with sqlite3.connect(CACHE_DB) as conn:
                conn.execute("DELETE FROM poi_cache")
                conn.commit()
            logger.info("POI cache cleared")
        except sqlite3.Error as e:
            logger.error(f"Cache clear failed: {e}")

    def clear_expired_cache(self) -> int:
        """Clear expired cache entries.

        Returns:
            Number of entries removed.
        """
        if not self.use_cache:
            return 0

        try:
            cutoff = time.time() - self.cache_ttl

            with sqlite3.connect(CACHE_DB) as conn:
                cursor = conn.execute(
                    "DELETE FROM poi_cache WHERE created_at < ?",
                    (cutoff,),
                )
                conn.commit()
                return cursor.rowcount

        except sqlite3.Error as e:
            logger.error(f"Cache cleanup failed: {e}")
            return 0
