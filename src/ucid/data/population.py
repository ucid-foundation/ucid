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

"""Population data integration for UCID analysis.

This module provides functions for integrating population data from sources
like WorldPop and GHS-POP to enable per-capita metric calculations and
population-weighted analysis.
"""


def get_population_estimate(
    lat: float,
    lon: float,
    radius_km: float = 1.0,
) -> float:
    """Get population estimate for a circular area around a location.

    This is a stub implementation that returns approximate values.
    Full implementation would query WorldPop, GHS-POP, or census data.

    Args:
        lat: Latitude in decimal degrees (-90 to 90).
        lon: Longitude in decimal degrees (-180 to 180).
        radius_km: Radius of the circular area in kilometers. Defaults to 1.0.

    Returns:
        Estimated population count within the specified area.

    Note:
        This is a stub that approximates population based on area.
        Actual implementation would use gridded population datasets.

    Example:
        >>> pop = get_population_estimate(41.015, 28.979, radius_km=0.5)
        >>> print(f"Estimated population: {pop:.0f}")
    """
    del lat, lon  # Unused in stub
    # Simple area-based approximation (placeholder)
    return 1000.0 * (radius_km * radius_km)


def normalize_by_population(value: float, population: float) -> float:
    """Calculate a per-capita metric.

    Divides a raw metric value by population to enable fair comparisons
    across areas with different population densities.

    Args:
        value: The raw metric value to normalize.
        population: The population count to normalize by.

    Returns:
        Per-capita value. Returns 0.0 if population is zero to avoid
        division errors.

    Example:
        >>> amenities = 50
        >>> population = 10000
        >>> per_capita = normalize_by_population(amenities, population)
        >>> print(f"Amenities per person: {per_capita:.4f}")
    """
    if population == 0:
        return 0.0
    return value / population
