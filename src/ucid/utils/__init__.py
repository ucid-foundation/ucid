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

"""UCID Utilities module.

This module provides common utilities including logging configuration,
validation helpers, and type definitions.
"""

from ucid.utils.logging import configure_logging, get_logger
from ucid.utils.validation import (
    validate_city_code,
    validate_coordinates,
    validate_grade,
    validate_timestamp,
)

__all__ = [
    "configure_logging",
    "get_logger",
    "validate_coordinates",
    "validate_city_code",
    "validate_timestamp",
    "validate_grade",
]
