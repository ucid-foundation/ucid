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

"""Event storage abstraction for UCID realtime data.

This module provides abstract and concrete implementations for
storing and querying realtime events.
"""

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class EventStore(ABC):
    """Abstract base class for event storage.

    Defines the interface for storing and querying events.
    Implementations may use memory, files, or databases.
    """

    @abstractmethod
    def store(self, event: dict[str, Any]) -> str:
        """Store an event and return its ID.

        Args:
            event: Event data to store.

        Returns:
            Unique identifier for the stored event.
        """

    @abstractmethod
    def query(self, event_filter: dict[str, Any]) -> list[dict[str, Any]]:
        """Query events matching the filter.

        Args:
            event_filter: Key-value pairs for exact matching.

        Returns:
            List of matching events.
        """


class InMemoryEventStore(EventStore):
    """Volatile in-memory event store.

    Useful for testing and development. Events are lost on restart.

    Example:
        >>> store = InMemoryEventStore()
        >>> event_id = store.store({"type": "score", "value": 85.0})
    """

    def __init__(self) -> None:
        """Initialize the in-memory store."""
        self._events: list[dict[str, Any]] = []

    def store(self, event: dict[str, Any]) -> str:
        """Store an event in memory.

        Args:
            event: Event data to store.

        Returns:
            Auto-generated event ID.
        """
        event_copy = event.copy()
        event_copy["_id"] = str(len(self._events))
        event_copy["_ts"] = time.time()
        self._events.append(event_copy)
        return event_copy["_id"]

    def query(self, event_filter: dict[str, Any]) -> list[dict[str, Any]]:
        """Query events matching the filter.

        Args:
            event_filter: Key-value pairs for exact matching.

        Returns:
            List of matching events.
        """
        results: list[dict[str, Any]] = []
        for evt in self._events:
            if all(evt.get(k) == v for k, v in event_filter.items()):
                results.append(evt)
        return results


class FileEventStore(EventStore):
    """Persistent append-only log event store.

    Stores events as newline-delimited JSON (JSONL) for durability.

    Attributes:
        log_path: Path to the JSONL log file.

    Example:
        >>> store = FileEventStore("events.jsonl")
        >>> store.store({"type": "score", "value": 85.0})
    """

    def __init__(self, log_path: str | Path = "events.jsonl") -> None:
        """Initialize the file event store.

        Args:
            log_path: Path to the log file. Parent directories created if needed.
        """
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def store(self, event: dict[str, Any]) -> str:
        """Store an event to the log file.

        Args:
            event: Event data to store.

        Returns:
            Offset-based event ID.
        """
        event_copy = event.copy()
        event_copy["_ts"] = time.time()

        try:
            current_size = self.log_path.stat().st_size
        except FileNotFoundError:
            current_size = 0

        event_copy["_id"] = str(current_size)

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_copy) + "\n")

        return event_copy["_id"]

    def query(self, event_filter: dict[str, Any]) -> list[dict[str, Any]]:
        """Query events from the log file.

        Args:
            event_filter: Key-value pairs for exact matching.

        Returns:
            List of matching events.
        """
        results: list[dict[str, Any]] = []

        if not self.log_path.exists():
            return results

        with open(self.log_path, encoding="utf-8") as f:
            for line in f:
                try:
                    evt = json.loads(line)
                    if all(evt.get(k) == v for k, v in event_filter.items()):
                        results.append(evt)
                except json.JSONDecodeError:
                    continue

        return results
