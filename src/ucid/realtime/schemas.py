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

"""Event schema definitions for UCID realtime data.

This module provides Pydantic models for validating and
serializing realtime sensor events.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SensorEvent(BaseModel):
    """Schema for a realtime sensor event.

    Represents a single reading from a sensor at a specific location.

    Attributes:
        sensor_id: Unique identifier for the sensor.
        timestamp: When the reading was taken.
        location: (latitude, longitude) tuple.
        reading_type: Type of reading (e.g., "temperature", "noise").
        value: Measured value.
        unit: Unit of measurement.
        quality: Data quality indicator (0.0-1.0).
        metadata: Additional key-value metadata.

    Example:
        >>> event = SensorEvent(
        ...     sensor_id="sensor-001",
        ...     timestamp=datetime.now(),
        ...     location=(41.015, 28.979),
        ...     reading_type="temperature",
        ...     value=25.5,
        ...     unit="celsius",
        ...     quality=0.95,
        ...     metadata={"source": "urban-grid"},
        ... )
    """

    sensor_id: str = Field(..., description="Unique sensor identifier")
    timestamp: datetime = Field(..., description="Reading timestamp")
    location: tuple[float, float] = Field(..., description="(lat, lon) coordinates")
    reading_type: str = Field(..., description="Type of reading")
    value: float = Field(..., description="Measured value")
    unit: str = Field(..., description="Unit of measurement")
    quality: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Quality indicator (0-1)",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )
