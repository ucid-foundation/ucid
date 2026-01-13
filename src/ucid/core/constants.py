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

"""Constants and configuration values for UCID.

This module defines magic numbers, thresholds, and configuration constants
used throughout the UCID library. All constants should be defined here to
maintain a single source of truth.
"""

from collections.abc import Mapping

# UCID Format Version
UCID_VERSION_PREFIX: str = "UCID-V1"
"""Full version prefix for UCID strings."""

UCID_CURRENT_VERSION: str = "V1"
"""Current schema version."""

# Geographic Bounds
MIN_LAT: float = -90.0
"""Minimum valid latitude."""

MAX_LAT: float = 90.0
"""Maximum valid latitude."""

MIN_LON: float = -180.0
"""Minimum valid longitude."""

MAX_LON: float = 180.0
"""Maximum valid longitude."""

# H3 Spatial Indexing
DEFAULT_H3_RESOLUTION: int = 9
"""Default H3 resolution (approximately 174m edge length)."""

MIN_H3_RESOLUTION: int = 0
"""Minimum H3 resolution level."""

MAX_H3_RESOLUTION: int = 15
"""Maximum H3 resolution level."""

# Grading System
VALID_GRADES: frozenset[str] = frozenset({"A+", "A", "B", "C", "D", "F"})
"""Set of valid letter grades."""

GRADE_THRESHOLDS: Mapping[str, float] = {
    "A+": 90.0,
    "A": 80.0,
    "B": 70.0,
    "C": 60.0,
    "D": 50.0,
    "F": 0.0,
}
"""Minimum score thresholds for each grade."""

# Built-in Contexts
BUILTIN_CONTEXTS: frozenset[str] = frozenset(
    {
        "15MIN",
        "TRANSIT",
        "CLIMATE",
        "VITALITY",
        "EQUITY",
        "WALK",
    }
)
"""Set of built-in context identifiers."""

# Reserved City Codes (for testing/development)
RESERVED_CITY_CODES: frozenset[str] = frozenset({"TST", "DEV", "TMP"})
"""City codes reserved for testing and development."""

# Validation Settings
STRICT_MODE_DEFAULT: bool = True
"""Default strict mode setting for validation."""

# Cache Settings
DEFAULT_CACHE_EXPIRY_DAYS: int = 30
"""Default cache expiry in days."""

# API Settings
DEFAULT_API_PORT: int = 8000
"""Default port for the API server."""

DEFAULT_API_HOST: str = "0.0.0.0"
"""Default host binding for the API server."""
