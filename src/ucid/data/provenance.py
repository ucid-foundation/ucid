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

"""Data provenance tracking for UCID datasets.

This module provides data structures for tracking the origin, licensing,
and quality of data sources used in UCID analysis. Provenance metadata
is essential for reproducibility and attribution.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class DataProvenance:
    """Provenance metadata for a dataset.

    Tracks the origin, licensing, and quality information for data
    used in UCID analysis. Attach provenance to computed results
    for transparency and reproducibility.

    Attributes:
        source: Identifier or name of the data source.
        url: URL where the data can be accessed (optional).
        license: License identifier (e.g., "ODbL", "CC BY 4.0").
        attribution: Required attribution text.
        version: Version or timestamp of the data.
        acquired: ISO 8601 timestamp when data was acquired.
        quality: Quality score from 0.0 (low) to 1.0 (high).
        metadata: Additional metadata as key-value pairs.

    Example:
        >>> provenance = DataProvenance(
        ...     source="OpenStreetMap",
        ...     url="https://www.openstreetmap.org",
        ...     license="ODbL",
        ...     attribution="© OpenStreetMap contributors",
        ...     version="2026-01-12",
        ...     acquired="2026-01-12T10:30:00Z",
        ...     quality=0.95,
        ...     metadata={"region": "Istanbul"},
        ... )
    """

    source: str
    license: str
    attribution: str
    url: str | None = None
    version: str = "latest"
    acquired: str = ""
    quality: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


def create_provenance(
    source: str,
    license_id: str,
    url: str | None = None,
) -> DataProvenance:
    """Create a provenance record with default values.

    Helper function to create a DataProvenance instance with
    automatically generated timestamp and default attribution.

    Args:
        source: Name or identifier of the data source.
        license_id: License identifier (e.g., "ODbL", "CC BY 4.0").
        url: Optional URL where the data can be accessed.

    Returns:
        A DataProvenance instance with generated defaults.

    Example:
        >>> prov = create_provenance("OpenStreetMap", "ODbL")
        >>> print(prov.attribution)
        © OpenStreetMap
    """
    return DataProvenance(
        source=source,
        url=url,
        license=license_id,
        attribution=f"© {source}",
        version="latest",
        acquired=datetime.now(UTC).isoformat(),
        quality=1.0,
        metadata={},
    )
