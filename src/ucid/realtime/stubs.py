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

"""Safe-by-default stub implementations for testing.

This module provides stub implementations of realtime components
that log operations but don't persist to external systems.
"""

import logging
from typing import Any

from ucid.realtime.ingestor import RealtimeIngestor

logger = logging.getLogger(__name__)


class StubIngestor(RealtimeIngestor):
    """Memory-only ingestor for testing.

    Logs events but doesn't persist to database or external storage.
    Useful for development and integration testing.

    Example:
        >>> ingestor = StubIngestor()
        >>> ingestor.ingest({"type": "score", "value": 85})
    """

    def ingest(self, event: dict[str, Any]) -> None:
        """Log an event without persisting.

        Args:
            event: Event data to log.
        """
        logger.info("StubIngest: %s", event)

    def ingest_batch(self, events: list[dict[str, Any]]) -> None:
        """Log a batch of events without persisting.

        Args:
            events: List of events to log.
        """
        logger.info("StubIngest batch: %d events", len(events))

    def flush(self) -> None:
        """Flush operation (no-op for stub)."""
        pass
