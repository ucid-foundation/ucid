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

"""GTFS data management for UCID.

This module provides utilities for loading and managing GTFS transit
feeds, with support for multiple transit agencies.
"""

from pathlib import Path
from typing import Any


class GTFSManager:
    """Manages GTFS feeds for UCID context analysis.

    This class provides a unified interface for loading GTFS feeds
    from various transit agencies.

    Attributes:
        cache_dir: Directory for caching downloaded feeds.
        known_feeds: Dictionary mapping city codes to feed URLs.

    Example:
        >>> manager = GTFSManager()
        >>> url = manager.get_feed_url("HEL")
        >>> feed = manager.load_feed(url)
    """

    def __init__(self, cache_dir: str | Path = ".cache/gtfs") -> None:
        """Initialize the GTFS manager.

        Args:
            cache_dir: Directory for caching downloaded feeds.
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.known_feeds: dict[str, str] = {
            "HEL": "https://infopalvelut.storage.hsldev.com/gtfs/hsl.zip",
            "PDX": "http://developer.trimet.org/schedule/gtfs.zip",
            "NYC": "https://rrgtfsfeeds.s3.amazonaws.com/gtfs_subway.zip",
            "BOS": "https://cdn.mbta.com/MBTA_GTFS.zip",
            "SYD": "manual-download-required",
            "IST": "manual-download-required-ibb",
        }

    def get_feed_url(self, city_code: str) -> str:
        """Get the GTFS feed URL for a city.

        Args:
            city_code: 3-character city code.

        Returns:
            URL of the GTFS feed, or empty string if not found.
        """
        return self.known_feeds.get(city_code.upper(), "")

    def load_feed(self, path_or_url: str) -> dict[str, Any]:
        """Load a GTFS feed from path or URL.

        Args:
            path_or_url: Local path or URL to GTFS ZIP file.

        Returns:
            Parsed GTFS feed object (stub implementation).

        Note:
            Production implementation should use gtfs_kit.read_feed().
        """
        return {"routes": [], "stops": [], "source": path_or_url}

    def validate_feed(self, feed: dict[str, Any]) -> dict[str, Any]:
        """Validate a GTFS feed.

        Args:
            feed: Parsed GTFS feed object.

        Returns:
            Validation result with 'valid' status and 'warnings' list.
        """
        del feed  # Stub - not used in placeholder validation
        return {"valid": True, "warnings": []}
