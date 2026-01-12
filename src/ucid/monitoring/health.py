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

"""Health check endpoints and logic for UCID services.

This module provides functions for checking the health of
UCID services and their dependencies.
"""

from dataclasses import dataclass
from enum import Enum


class HealthStatus(str, Enum):
    """Health check status values."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class HealthCheckResult:
    """Result of a health check.

    Attributes:
        name: Name of the component checked.
        status: Health status.
        message: Optional status message.
        latency_ms: Optional latency in milliseconds.
    """

    name: str
    status: HealthStatus
    message: str = ""
    latency_ms: float | None = None


def check_dependencies() -> dict[str, HealthCheckResult]:
    """Check status of all dependencies.

    Returns:
        Dictionary mapping dependency names to health check results.

    Note:
        This is a stub implementation. Real implementation would
        perform actual connectivity checks.

    Example:
        >>> results = check_dependencies()
        >>> for name, result in results.items():
        ...     print(f"{name}: {result.status.value}")
    """
    return {
        "database": HealthCheckResult(
            name="database",
            status=HealthStatus.HEALTHY,
            message="Connected",
            latency_ms=5.0,
        ),
        "cache": HealthCheckResult(
            name="cache",
            status=HealthStatus.HEALTHY,
            message="Connected",
            latency_ms=1.0,
        ),
        "api": HealthCheckResult(
            name="api",
            status=HealthStatus.HEALTHY,
            message="Operational",
        ),
    }


def get_overall_health() -> HealthStatus:
    """Get the overall system health status.

    Returns:
        Overall health status based on all dependency checks.
    """
    results = check_dependencies()

    if any(r.status == HealthStatus.UNHEALTHY for r in results.values()):
        return HealthStatus.UNHEALTHY
    if any(r.status == HealthStatus.DEGRADED for r in results.values()):
        return HealthStatus.DEGRADED
    return HealthStatus.HEALTHY
