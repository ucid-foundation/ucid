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

"""Configuration management for UCID.

This module provides a simple configuration interface that reads
from environment variables. Supports string and boolean values.
"""

import os
from typing import Any


class Config:
    """Configuration loader from environment variables.

    Provides static methods to retrieve configuration values from
    environment variables with optional defaults.

    Example:
        >>> api_key = Config.get("UCID_API_KEY", "default-key")
        >>> debug_mode = Config.get_bool("UCID_DEBUG", False)
    """

    @staticmethod
    def get(key: str, default: Any = None) -> Any:
        """Get a configuration value from environment variables.

        Args:
            key: The environment variable name.
            default: Default value if not found. Defaults to None.

        Returns:
            The environment variable value, or the default.

        Example:
            >>> port = Config.get("UCID_PORT", "8000")
        """
        return os.environ.get(key, default)

    @staticmethod
    def get_bool(key: str, default: bool = False) -> bool:
        """Get a boolean configuration value.

        Interprets 'true', '1', 'yes', 'on' (case-insensitive) as True.
        All other values are interpreted as False.

        Args:
            key: The environment variable name.
            default: Default value if not found. Defaults to False.

        Returns:
            Boolean value of the configuration.

        Example:
            >>> debug = Config.get_bool("UCID_DEBUG", False)
        """
        val = os.environ.get(key, str(default)).lower()
        return val in ("true", "1", "yes", "on")

    @staticmethod
    def get_int(key: str, default: int = 0) -> int:
        """Get an integer configuration value.

        Args:
            key: The environment variable name.
            default: Default value if not found or invalid. Defaults to 0.

        Returns:
            Integer value of the configuration.

        Example:
            >>> workers = Config.get_int("UCID_WORKERS", 4)
        """
        try:
            return int(os.environ.get(key, str(default)))
        except ValueError:
            return default
