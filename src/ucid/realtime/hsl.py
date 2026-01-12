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

"""HSL (Helsinki) Realtime Connectors.

This module provides connectors for HSL (Helsingin seudun liikenne)
realtime transit feeds via GTFS-RT format.
"""

import time
import urllib.request
from typing import Any

from ucid.data.sources import DATASETS
from ucid.realtime.eventstore import EventStore
from ucid.realtime.ingestor import RealtimeIngestor


class HSLConnect:
    """Connector for HSL Realtime APIs.

    Provides access to HSL's GTFS-RT feeds including alerts,
    trip updates, and vehicle positions.

    Attributes:
        headers: Request headers including User-Agent.

    Example:
        >>> conn = HSLConnect()
        >>> raw_data = conn.fetch_feed("vehicle_positions")
    """

    ENDPOINTS: dict[str, str] = {
        "alerts": DATASETS["hsl_rt_alerts"].url,
        "trip_updates": DATASETS["hsl_rt_trip"].url,
        "vehicle_positions": DATASETS["hsl_rt_vehicle"].url,
    }

    def __init__(self, user_agent: str = "UCID/1.0") -> None:
        """Initialize the HSL connector.

        Args:
            user_agent: User-Agent header for requests.
        """
        self.headers = {"User-Agent": user_agent}

    def fetch_feed(self, feed_type: str) -> bytes:
        """Fetch raw GTFS-RT feed (Protobuf).

        Args:
            feed_type: Type of feed (alerts, trip_updates, vehicle_positions).

        Returns:
            Raw protobuf bytes.

        Raises:
            ValueError: If feed_type is unknown.
        """
        url = self.ENDPOINTS.get(feed_type)
        if not url:
            raise ValueError(f"Unknown feed type: {feed_type}")

        req = urllib.request.Request(url, headers=self.headers)
        with urllib.request.urlopen(req) as response:
            return response.read()


class HSLIngestor(RealtimeIngestor):
    """Ingestor specifically for HSL Realtime feeds.

    Parses GTFS-RT feeds and stores events.

    Note:
        Full protobuf parsing requires google-transit-gtfs-realtime-bindings.
        This implementation stores raw metadata as a stub.

    Attributes:
        connect: HSL connection handler.
        store_backend: Event store for persistence.
    """

    def __init__(self, store: EventStore) -> None:
        """Initialize the HSL ingestor.

        Args:
            store: Event store backend.
        """
        self.connect = HSLConnect()
        self.store_backend = store

    def ingest(self, event: dict[str, Any]) -> str:
        """Ingest a single event.

        Args:
            event: Event data to ingest.

        Returns:
            Event ID from store.
        """
        return self.store_backend.store(event)

    def ingest_batch(self, events: list[dict[str, Any]]) -> list[str]:
        """Ingest a batch of events.

        Args:
            events: List of events to ingest.

        Returns:
            List of event IDs.
        """
        return [self.ingest(e) for e in events]

    def flush(self) -> None:
        """Flush pending events (no-op for this implementation)."""
        pass

    def poll_vehicle_positions(self) -> bool:
        """Poll vehicle positions and store raw blob.

        Returns:
            True if successful, False otherwise.

        Note:
            Full implementation requires gtfs-realtime-bindings to parse protobuf.
        """
        try:
            raw_data = self.connect.fetch_feed("vehicle_positions")

            event = {
                "source": "hsl_rt_vehicle",
                "timestamp": time.time(),
                "size_bytes": len(raw_data),
                "raw_blob_preview": str(raw_data[:20]),
            }
            self.store_backend.store(event)
            return True
        except Exception:
            return False
