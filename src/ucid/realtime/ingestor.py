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

"""Realtime event ingestion for UCID.

This module provides interfaces for ingesting streaming urban data.
All realtime endpoints are disabled by default for security.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class SensorEvent:
    """Represents a sensor reading event.

    Attributes:
        sensor_id: Unique identifier for the sensor.
        timestamp: When the reading was taken.
        lat: Latitude of sensor location.
        lon: Longitude of sensor location.
        reading_type: Type of reading (temperature, air_quality, etc.).
        value: Measured value.
        unit: Unit of measurement.
        quality: Data quality score (0-1).
        metadata: Additional metadata.
    """

    sensor_id: str
    timestamp: datetime
    lat: float
    lon: float
    reading_type: str
    value: float
    unit: str
    quality: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


class RealtimeIngestor(ABC):
    """Abstract interface for realtime event ingestion.

    All implementations must be explicitly enabled via configuration.
    Network ingestion is disabled by default for security.
    """

    @abstractmethod
    def ingest(self, event: SensorEvent) -> str:
        """Ingest a single event.

        Args:
            event: Sensor event to ingest.

        Returns:
            Event ID.
        """

    @abstractmethod
    def ingest_batch(self, events: list[SensorEvent]) -> list[str]:
        """Ingest batch of events.

        Args:
            events: List of sensor events.

        Returns:
            List of event IDs.
        """

    @abstractmethod
    def flush(self) -> None:
        """Force flush pending events."""


class StubIngestor(RealtimeIngestor):
    """Safe-by-default stub ingestor.

    This implementation stores events in memory only and does not
    accept network input. Use for testing and development.
    """

    def __init__(self) -> None:
        """Initialize the stub ingestor."""
        self._events: list[SensorEvent] = []
        self._counter = 0

    def ingest(self, event: SensorEvent) -> str:
        """Ingest a single event to memory.

        Args:
            event: Sensor event to ingest.

        Returns:
            Event ID.
        """
        self._counter += 1
        event_id = f"evt_{self._counter:08d}"
        self._events.append(event)
        return event_id

    def ingest_batch(self, events: list[SensorEvent]) -> list[str]:
        """Ingest batch of events to memory.

        Args:
            events: List of sensor events.

        Returns:
            List of event IDs.
        """
        return [self.ingest(e) for e in events]

    def flush(self) -> None:
        """Flush is a no-op for stub ingestor."""
        pass

    def get_events(self) -> list[SensorEvent]:
        """Get all ingested events.

        Returns:
            List of stored events.
        """
        return list(self._events)

    def clear(self) -> None:
        """Clear all stored events."""
        self._events.clear()
