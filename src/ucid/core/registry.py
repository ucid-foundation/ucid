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
    _lock: threading.RLock = threading.RLock()  # RLock allows re-entrant locking

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
        """Load all 451 cities from cities_registry.json."""
        import json
        from pathlib import Path

        # Load from JSON registry
        registry_path = Path(__file__).parent.parent / "data" / "cities_registry.json"

        with open(registry_path, encoding="utf-8") as f:
            registry = json.load(f)

        cities_data = registry.get("cities", {})

        for country_key, country_info in cities_data.items():
            country_code = country_info.get("country_code", "XX")
            timezone = country_info.get("timezone", "UTC")

            for city_data in country_info.get("cities", []):
                name = city_data.get("name", "")
                # Generate unique 3-letter code
                code = self._generate_city_code(name, country_code)

                if code and code not in self._cities:
                    city = City(
                        code=code,
                        full_name=name,
                        country=country_code,
                        timezone=timezone,
                        population=city_data.get("population", 0),
                    )
                    self._cities[code] = city

        # Add test/dev codes
        self._cities["TST"] = City(code="TST", full_name="Test City", country="XX", timezone="UTC")
        self._cities["DEV"] = City(code="DEV", full_name="Development", country="XX", timezone="UTC")

    def _generate_city_code(self, name: str, country_code: str) -> str:
        """Generate a unique 3-letter city code from city name.

        Uses multiple strategies to ensure uniqueness:
        1. First 3 letters of name
        2. First letter + 2 consonants
        3. First 2 letters + country initial
        4. Country code + first letter
        5. Various other letter combinations
        """
        import re
        # Clean name - keep only letters
        clean = re.sub(r"[^A-Za-z]", "", name).upper()
        if len(clean) < 2:
            clean = (clean + country_code).upper()

        # Strategy 1: First 3 letters
        code = clean[:3].ljust(3, "X")
        if code not in self._cities and code.isalpha():
            return code

        # Strategy 2: First letter + positions 2,3
        if len(clean) >= 4:
            code = clean[0] + clean[2] + clean[3]
            if code not in self._cities and code.isalpha():
                return code

        # Strategy 3: First 2 + country initial
        code = clean[:2] + country_code[0]
        if code not in self._cities and code.isalpha():
            return code

        # Strategy 4: Country code + first letter
        code = country_code + clean[0]
        if code not in self._cities and code.isalpha():
            return code

        # Strategy 5: First + last + middle
        if len(clean) >= 3:
            code = clean[0] + clean[-1] + clean[len(clean)//2]
            if code not in self._cities and code.isalpha():
                return code

        # Strategy 6: Try consonants only
        consonants = re.sub(r"[AEIOU]", "", clean)
        if len(consonants) >= 3:
            code = consonants[:3]
            if code not in self._cities and code.isalpha():
                return code

        # Strategy 7: Iterate through all 3-letter combinations
        for i in range(len(clean) - 2):
            code = clean[i:i+3]
            if len(code) == 3 and code not in self._cities and code.isalpha():
                return code

        # Strategy 8: Use letters A-Z as suffix with first 2 chars
        for suffix in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            code = clean[:2] + suffix
            if code not in self._cities and len(code) == 3 and code.isalpha():
                return code

        # Strategy 9: Use country code prefix with all possible suffixes
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            code = country_code + letter
            if code not in self._cities and len(code) == 3 and code.isalpha():
                return code

        # Strategy 10: Use first char + two letters from alphabet
        for l1 in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            for l2 in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                code = clean[0] + l1 + l2
                if code not in self._cities and code.isalpha():
                    return code

        # Return first 3 anyway (should never reach here with 451 cities)
        return clean[:3].ljust(3, "X")


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
