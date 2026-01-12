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

"""Alerting rules and conditions for UCID monitoring.

This module provides functions for checking metrics against
thresholds and generating alerts.
"""

import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Alert:
    """An alert triggered by a metric condition.

    Attributes:
        name: Short name for the alert.
        message: Descriptive message.
        severity: Alert severity level.
        metric_name: Name of the metric that triggered the alert.
        metric_value: Value of the metric.
        threshold: Threshold that was exceeded.
    """

    name: str
    message: str
    severity: AlertSeverity
    metric_name: str
    metric_value: float
    threshold: float


def check_alert_conditions(metrics: dict[str, float]) -> list[Alert]:
    """Check metrics against thresholds and return triggered alerts.

    Args:
        metrics: Dictionary of metric names to values.

    Returns:
        List of Alert objects for conditions that were triggered.

    Example:
        >>> alerts = check_alert_conditions({"error_rate": 0.1, "latency_p95": 2.0})
        >>> for alert in alerts:
        ...     print(f"{alert.severity.value}: {alert.message}")
    """
    alerts: list[Alert] = []

    error_rate = metrics.get("error_rate", 0)
    if error_rate > 0.05:
        alert = Alert(
            name="high_error_rate",
            message=f"High error rate detected: {error_rate:.1%} > 5%",
            severity=AlertSeverity.WARNING,
            metric_name="error_rate",
            metric_value=error_rate,
            threshold=0.05,
        )
        alerts.append(alert)
        logger.warning(alert.message)

    latency = metrics.get("latency_p95", 0)
    if latency > 1.0:
        alert = Alert(
            name="high_latency",
            message=f"High latency detected: {latency:.2f}s > 1.0s",
            severity=AlertSeverity.WARNING,
            metric_name="latency_p95",
            metric_value=latency,
            threshold=1.0,
        )
        alerts.append(alert)
        logger.warning(alert.message)

    return alerts
