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

"""Custom type definitions for UCID.

This module defines type aliases and NewType definitions used throughout
the UCID codebase for improved type safety and documentation.
"""

from typing import Any, NewType

# Type aliases for geographic data
GeoJSON = dict[str, str | float | list[float] | dict[str, Any]]
"""GeoJSON-compatible dictionary type."""

Coordinate = tuple[float, float]
"""A (latitude, longitude) coordinate pair."""

H3Index = str
"""An H3 hexagonal index string."""

# NewType definitions for semantic types
Confidence = NewType("Confidence", float)
"""Confidence score from 0.0 to 1.0."""

Grade = NewType("Grade", str)
"""Quality grade (A+, A, B, C, D, F)."""

CityCode = NewType("CityCode", str)
"""3-character city code (e.g., IST, NYC, HEL)."""

Timestamp = NewType("Timestamp", str)
"""ISO week timestamp (e.g., 2026W01T12)."""

ContextID = NewType("ContextID", str)
"""Context identifier (e.g., 15MIN, TRANSIT, WALK)."""
