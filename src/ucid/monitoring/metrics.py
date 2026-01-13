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

"""Metrics collection for UCID.

This module provides Prometheus-compatible metrics for monitoring.
"""

from typing import Any


class MetricsCollector:
    """Collector for UCID application metrics.

    Provides counters, gauges, and histograms for monitoring.
    """

    def __init__(self) -> None:
        """Initialize the metrics collector."""
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}

    def increment(self, name: str, value: int = 1, labels: dict[str, str] | None = None) -> None:
        """Increment a counter.

        Args:
            name: Counter name.
            value: Amount to increment.
            labels: Optional labels.
        """
        key = self._make_key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Set a gauge value.

        Args:
            name: Gauge name.
            value: Value to set.
            labels: Optional labels.
        """
        key = self._make_key(name, labels)
        self._gauges[key] = value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Record a histogram observation.

        Args:
            name: Histogram name.
            value: Value to observe.
            labels: Optional labels.
        """
        key = self._make_key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)

    def _make_key(self, name: str, labels: dict[str, str] | None = None) -> str:
        """Create a unique key from name and labels."""
        if labels:
            label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
            return f"{name}{{{label_str}}}"
        return name

    def get_metrics(self) -> dict[str, Any]:
        """Get all collected metrics.

        Returns:
            Dictionary of all metrics.
        """
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {k: {"count": len(v), "sum": sum(v)} for k, v in self._histograms.items()},
        }


# Global metrics instance
metrics = MetricsCollector()
