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

"""GTFS (General Transit Feed Specification) client for UCID.

This module provides functionality to download, parse, and analyze
GTFS transit feeds for transit accessibility scoring.

Example:
    >>> from ucid.data.gtfs_client import GTFSClient
    >>> client = GTFSClient()
    >>> stops = client.get_stops_near(40.4093, 49.8671, radius=1000)
"""

from __future__ import annotations

import csv
import io
import logging
import zipfile
from dataclasses import dataclass
from datetime import datetime, time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Known GTFS feed sources
GTFS_FEEDS = {
    "baku": "https://transitfeeds.com/p/baku-metro/1234/latest/download",
    "istanbul": "https://data.ibb.gov.tr/dataset/gtfs.zip",
    "helsinki": "https://transitfeeds.com/p/hsl/735/latest/download",
    "berlin": "https://transitfeeds.com/p/vbb/405/latest/download",
}

# Cache directory
CACHE_DIR = Path.home() / ".ucid" / "cache" / "gtfs"


@dataclass
class Stop:
    """GTFS stop representation.

    Attributes:
        stop_id: Unique stop identifier.
        stop_name: Human-readable stop name.
        stop_lat: Stop latitude.
        stop_lon: Stop longitude.
        stop_type: Type of stop (0=stop, 1=station).
        parent_station: Parent station ID if applicable.
    """

    stop_id: str
    stop_name: str
    stop_lat: float
    stop_lon: float
    stop_type: int = 0
    parent_station: str | None = None


@dataclass
class Route:
    """GTFS route representation.

    Attributes:
        route_id: Unique route identifier.
        route_short_name: Short route name (e.g., "M1").
        route_long_name: Full route name.
        route_type: GTFS route type (0=tram, 1=metro, 2=rail, 3=bus).
    """

    route_id: str
    route_short_name: str
    route_long_name: str
    route_type: int


@dataclass
class StopTime:
    """GTFS stop time representation.

    Attributes:
        trip_id: Trip identifier.
        stop_id: Stop identifier.
        arrival_time: Arrival time.
        departure_time: Departure time.
        stop_sequence: Order of stop in trip.
    """

    trip_id: str
    stop_id: str
    arrival_time: time | None
    departure_time: time | None
    stop_sequence: int


class GTFSError(Exception):
    """Base exception for GTFS operations."""

    pass


class GTFSClient:
    """Client for GTFS feed operations.

    This client downloads, caches, and parses GTFS feeds to provide
    transit accessibility metrics.

    Attributes:
        cache_dir: Directory for cached GTFS data.

    Example:
        >>> client = GTFSClient()
        >>> client.load_feed("helsinki")
        >>> stops = client.get_stops_near(60.169, 24.938, radius=500)
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        """Initialize GTFS client.

        Args:
            cache_dir: Cache directory path. Defaults to ~/.ucid/cache/gtfs.
        """
        self.cache_dir = cache_dir or CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.stops: dict[str, Stop] = {}
        self.routes: dict[str, Route] = {}
        self.stop_times: list[StopTime] = []
        self._loaded_feed: str | None = None

    def download_feed(self, feed_url: str, feed_name: str) -> Path:
        """Download GTFS feed.

        Args:
            feed_url: URL to download feed from.
            feed_name: Name for local cache.

        Returns:
            Path to downloaded feed.
        """
        cache_path = self.cache_dir / f"{feed_name}.zip"

        if cache_path.exists():
            logger.info(f"Using cached feed: {cache_path}")
            return cache_path

        logger.info(f"Downloading GTFS feed from {feed_url}")

        try:
            with httpx.Client(timeout=60.0, follow_redirects=True) as client:
                response = client.get(feed_url)
                response.raise_for_status()

                with open(cache_path, "wb") as f:
                    f.write(response.content)

            logger.info(f"Downloaded feed to {cache_path}")
            return cache_path

        except httpx.HTTPError as e:
            raise GTFSError(f"Failed to download feed: {e}") from e

    def load_feed(self, feed_name: str) -> None:
        """Load GTFS feed by name.

        Args:
            feed_name: Feed name (must be in GTFS_FEEDS).

        Raises:
            GTFSError: If feed not found or invalid.
        """
        if feed_name not in GTFS_FEEDS:
            # Try loading from local cache
            cache_path = self.cache_dir / f"{feed_name}.zip"
            if not cache_path.exists():
                raise GTFSError(f"Unknown feed: {feed_name}")
        else:
            feed_url = GTFS_FEEDS[feed_name]
            cache_path = self.download_feed(feed_url, feed_name)

        self._parse_feed(cache_path)
        self._loaded_feed = feed_name

    def load_feed_from_path(self, feed_path: Path) -> None:
        """Load GTFS feed from local path.

        Args:
            feed_path: Path to GTFS zip file.
        """
        if not feed_path.exists():
            raise GTFSError(f"Feed file not found: {feed_path}")

        self._parse_feed(feed_path)
        self._loaded_feed = feed_path.stem

    def _parse_feed(self, feed_path: Path) -> None:
        """Parse GTFS zip file.

        Args:
            feed_path: Path to GTFS zip file.
        """
        logger.info(f"Parsing GTFS feed: {feed_path}")

        self.stops.clear()
        self.routes.clear()
        self.stop_times.clear()

        try:
            with zipfile.ZipFile(feed_path, "r") as zf:
                # Parse stops.txt
                if "stops.txt" in zf.namelist():
                    with zf.open("stops.txt") as f:
                        self._parse_stops(io.TextIOWrapper(f, encoding="utf-8-sig"))

                # Parse routes.txt
                if "routes.txt" in zf.namelist():
                    with zf.open("routes.txt") as f:
                        self._parse_routes(io.TextIOWrapper(f, encoding="utf-8-sig"))

                # Parse stop_times.txt (sample only for memory efficiency)
                if "stop_times.txt" in zf.namelist():
                    with zf.open("stop_times.txt") as f:
                        self._parse_stop_times(
                            io.TextIOWrapper(f, encoding="utf-8-sig"),
                            max_rows=100000,
                        )

            logger.info(
                f"Loaded {len(self.stops)} stops, {len(self.routes)} routes, "
                f"{len(self.stop_times)} stop times"
            )

        except zipfile.BadZipFile as e:
            raise GTFSError(f"Invalid GTFS zip file: {e}") from e

    def _parse_stops(self, file: io.TextIOWrapper) -> None:
        """Parse stops.txt file."""
        reader = csv.DictReader(file)

        for row in reader:
            try:
                stop = Stop(
                    stop_id=row["stop_id"],
                    stop_name=row.get("stop_name", ""),
                    stop_lat=float(row["stop_lat"]),
                    stop_lon=float(row["stop_lon"]),
                    stop_type=int(row.get("location_type", 0)),
                    parent_station=row.get("parent_station") or None,
                )
                self.stops[stop.stop_id] = stop
            except (KeyError, ValueError) as e:
                logger.debug(f"Skipping invalid stop row: {e}")

    def _parse_routes(self, file: io.TextIOWrapper) -> None:
        """Parse routes.txt file."""
        reader = csv.DictReader(file)

        for row in reader:
            try:
                route = Route(
                    route_id=row["route_id"],
                    route_short_name=row.get("route_short_name", ""),
                    route_long_name=row.get("route_long_name", ""),
                    route_type=int(row.get("route_type", 3)),
                )
                self.routes[route.route_id] = route
            except (KeyError, ValueError) as e:
                logger.debug(f"Skipping invalid route row: {e}")

    def _parse_stop_times(
        self,
        file: io.TextIOWrapper,
        max_rows: int = 100000,
    ) -> None:
        """Parse stop_times.txt file with row limit."""
        reader = csv.DictReader(file)

        for i, row in enumerate(reader):
            if i >= max_rows:
                break

            try:
                stop_time = StopTime(
                    trip_id=row["trip_id"],
                    stop_id=row["stop_id"],
                    arrival_time=self._parse_time(row.get("arrival_time", "")),
                    departure_time=self._parse_time(row.get("departure_time", "")),
                    stop_sequence=int(row.get("stop_sequence", 0)),
                )
                self.stop_times.append(stop_time)
            except (KeyError, ValueError) as e:
                logger.debug(f"Skipping invalid stop_time row: {e}")

    @staticmethod
    def _parse_time(time_str: str) -> time | None:
        """Parse GTFS time string (may exceed 24:00:00)."""
        if not time_str:
            return None

        try:
            parts = time_str.split(":")
            hours = int(parts[0]) % 24  # Handle times > 24:00
            minutes = int(parts[1])
            seconds = int(parts[2]) if len(parts) > 2 else 0
            return time(hours, minutes, seconds)
        except (ValueError, IndexError):
            return None

    def get_stops_near(
        self,
        lat: float,
        lon: float,
        radius: float = 1000.0,
    ) -> list[Stop]:
        """Get stops within radius of a point.

        Args:
            lat: Center latitude.
            lon: Center longitude.
            radius: Search radius in meters.

        Returns:
            List of stops within radius.
        """
        nearby: list[Stop] = []
        radius_deg = radius / 111000  # Approximate meters to degrees

        for stop in self.stops.values():
            dist = ((stop.stop_lat - lat) ** 2 + (stop.stop_lon - lon) ** 2) ** 0.5
            if dist <= radius_deg:
                nearby.append(stop)

        return nearby

    def get_stop_frequency(
        self,
        stop_id: str,
        start_hour: int = 7,
        end_hour: int = 19,
    ) -> float:
        """Calculate average departures per hour for a stop.

        Args:
            stop_id: Stop identifier.
            start_hour: Start of analysis window.
            end_hour: End of analysis window.

        Returns:
            Average departures per hour.
        """
        departures = [
            st
            for st in self.stop_times
            if st.stop_id == stop_id
            and st.departure_time
            and start_hour <= st.departure_time.hour < end_hour
        ]

        hours = end_hour - start_hour
        return len(departures) / hours if hours > 0 else 0.0

    def get_route_types_at_stop(self, stop_id: str) -> set[int]:
        """Get route types serving a stop.

        Args:
            stop_id: Stop identifier.

        Returns:
            Set of route type codes (0=tram, 1=metro, 2=rail, 3=bus).
        """
        # This would require trips.txt for full implementation
        # For now, return empty set
        return set()

    def calculate_transit_score(
        self,
        lat: float,
        lon: float,
        radius: float = 500.0,
    ) -> dict[str, Any]:
        """Calculate transit accessibility score for a location.

        Args:
            lat: Location latitude.
            lon: Location longitude.
            radius: Search radius in meters.

        Returns:
            Dictionary with score components.
        """
        stops = self.get_stops_near(lat, lon, radius)

        if not stops:
            return {
                "score": 0.0,
                "stop_count": 0,
                "avg_frequency": 0.0,
                "mode_diversity": 0,
            }

        # Calculate metrics
        stop_count = len(stops)
        frequencies = [self.get_stop_frequency(s.stop_id) for s in stops]
        avg_frequency = sum(frequencies) / len(frequencies) if frequencies else 0.0

        # Score based on stops and frequency
        stop_score = min(stop_count / 10, 1.0) * 50  # Max 50 points for stops
        freq_score = min(avg_frequency / 6, 1.0) * 50  # Max 50 for 6+ per hour

        return {
            "score": stop_score + freq_score,
            "stop_count": stop_count,
            "avg_frequency": avg_frequency,
            "mode_diversity": 0,  # Would need trips.txt
        }
