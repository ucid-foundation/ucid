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

"""Thread-safe city registry for UCID.

This module provides a singleton registry for managing approved city
definitions. The registry is thread-safe and pre-loaded with common cities.

Example:
    >>> from ucid.core.registry import CityRegistry
    >>> registry = CityRegistry()
    >>> city = registry.get("IST")
    >>> print(city.full_name)
    Istanbul
"""

import threading

from ucid.core.errors import UCIDRegistryError
from ucid.core.models import City


class CityRegistry:
    """Thread-safe singleton registry for city definitions.

    This class implements the Singleton pattern to ensure a single,
    globally-accessible registry of cities. All operations are thread-safe.

    Attributes:
        _cities: Internal dictionary mapping city codes to City objects.
    """

    _instance: "CityRegistry | None" = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "CityRegistry":
        """Create or return the singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._cities: dict[str, City] = {}
                    instance._load_defaults()
                    cls._instance = instance
        return cls._instance

    def _load_defaults(self) -> None:
        """Load default cities into the registry."""
        defaults = [
            City(
                code="IST",
                full_name="Istanbul",
                country="TR",
                timezone="Europe/Istanbul",
                population=15462452,
            ),
            City(
                code="NYC",
                full_name="New York City",
                country="US",
                timezone="America/New_York",
                population=8804190,
            ),
            City(
                code="LON",
                full_name="London",
                country="GB",
                timezone="Europe/London",
                population=8982000,
            ),
            City(
                code="HEL",
                full_name="Helsinki",
                country="FI",
                timezone="Europe/Helsinki",
                population=631695,
            ),
            City(
                code="PDX",
                full_name="Portland",
                country="US",
                timezone="America/Los_Angeles",
                population=652503,
            ),
            City(
                code="BOS",
                full_name="Boston",
                country="US",
                timezone="America/New_York",
                population=675647,
            ),
            City(
                code="SYD",
                full_name="Sydney",
                country="AU",
                timezone="Australia/Sydney",
                population=5312163,
            ),
            # Reserved codes for testing
            City(code="TST", full_name="Test City", country="XX", timezone="UTC"),
            City(code="DEV", full_name="Development", country="XX", timezone="UTC"),
        ]
        for city in defaults:
            self.register(city)

    def register(self, city: City) -> None:
        """Register a new city in the registry.

        Args:
            city: City object to register.

        Note:
            If a city with the same code exists, it will be overwritten.
        """
        with self._lock:
            self._cities[city.code] = city

    def get(self, code: str) -> City:
        """Get a city by its code.

        Args:
            code: 3-character city code (case-insensitive).

        Returns:
            City object matching the code.

        Raises:
            UCIDRegistryError: If city code is not found.
        """
        code_upper = code.upper()
        with self._lock:
            if code_upper not in self._cities:
                raise UCIDRegistryError(
                    f"City code not found: {code_upper}",
                    code="CITY_NOT_FOUND",
                    details={"code": code_upper},
                )
            return self._cities[code_upper]

    def exists(self, code: str) -> bool:
        """Check if a city code exists in the registry.

        Args:
            code: 3-character city code.

        Returns:
            True if city exists, False otherwise.
        """
        with self._lock:
            return code.upper() in self._cities

    def list_all(self) -> list[City]:
        """List all registered cities.

        Returns:
            List of all City objects in the registry.
        """
        with self._lock:
            return list(self._cities.values())

    def count(self) -> int:
        """Return the number of registered cities."""
        with self._lock:
            return len(self._cities)
