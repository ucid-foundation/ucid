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

"""City registry synchronization tool for UCID library.

This tool synchronizes the city registry with external data sources
to ensure population, timezone, and coordinate data stays current.

Usage:
    python tools/sync_registry.py [options]

Examples:
    # Dry run (show changes without applying)
    python tools/sync_registry.py --dry-run

    # Apply updates
    python tools/sync_registry.py --apply

    # Update specific city
    python tools/sync_registry.py --city IST --apply

Data Sources:
    - Population: World Bank, UN Data
    - Timezones: IANA Time Zone Database
    - Coordinates: OpenStreetMap Nominatim

Validation:
    - Population changes > 10% are flagged
    - Coordinate changes > 0.1 degrees are flagged
    - New cities require manual approval
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class CityUpdate:
    """Pending city update."""

    code: str
    field: str
    old_value: Any
    new_value: Any
    source: str
    requires_review: bool = False


@dataclass
class SyncReport:
    """Synchronization report."""

    cities_checked: int = 0
    updates_found: int = 0
    updates_applied: int = 0
    reviews_required: int = 0
    updates: list[CityUpdate] = field(default_factory=list)


def load_registry(path: Path) -> dict:
    """Load city registry from JSON file.

    Args:
        path: Path to cities.json.

    Returns:
        Registry data.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def save_registry(path: Path, data: dict) -> None:
    """Save city registry to JSON file.

    Args:
        path: Path to cities.json.
        data: Registry data.
    """
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def fetch_population_update(city_code: str) -> int | None:
    """Fetch updated population for a city.

    Args:
        city_code: City code.

    Returns:
        Updated population or None if unavailable.

    Note:
        This is a placeholder. In production, this would call
        external APIs like World Bank or UN Data.
    """
    # Placeholder - would call real API
    return None


def fetch_timezone_update(lat: float, lon: float) -> str | None:
    """Fetch timezone for coordinates.

    Args:
        lat: Latitude.
        lon: Longitude.

    Returns:
        Timezone string or None if unavailable.

    Note:
        This is a placeholder. In production, this would use
        a timezone database lookup.
    """
    # Placeholder - would use real timezone lookup
    return None


def check_population_change(old: int, new: int) -> bool:
    """Check if population change requires review.

    Args:
        old: Old population.
        new: New population.

    Returns:
        True if change requires review.
    """
    if old == 0:
        return True
    change_pct = abs(new - old) / old * 100
    return change_pct > 10


def check_coordinate_change(
    old_lat: float,
    old_lon: float,
    new_lat: float,
    new_lon: float,
) -> bool:
    """Check if coordinate change requires review.

    Args:
        old_lat: Old latitude.
        old_lon: Old longitude.
        new_lat: New latitude.
        new_lon: New longitude.

    Returns:
        True if change requires review.
    """
    lat_change = abs(new_lat - old_lat)
    lon_change = abs(new_lon - old_lon)
    return lat_change > 0.1 or lon_change > 0.1


def sync_city(city: dict, report: SyncReport) -> list[CityUpdate]:
    """Synchronize a single city.

    Args:
        city: City data.
        report: Sync report to update.

    Returns:
        List of pending updates.
    """
    updates = []
    code = city.get("code", "")

    report.cities_checked += 1

    # Check population
    new_population = fetch_population_update(code)
    if new_population is not None:
        old_population = city.get("population", 0)
        if new_population != old_population:
            update = CityUpdate(
                code=code,
                field="population",
                old_value=old_population,
                new_value=new_population,
                source="World Bank",
                requires_review=check_population_change(old_population, new_population),
            )
            updates.append(update)
            report.updates_found += 1
            if update.requires_review:
                report.reviews_required += 1

    # Check timezone
    new_timezone = fetch_timezone_update(city.get("lat", 0), city.get("lon", 0))
    if new_timezone is not None:
        old_timezone = city.get("timezone", "")
        if new_timezone != old_timezone:
            update = CityUpdate(
                code=code,
                field="timezone",
                old_value=old_timezone,
                new_value=new_timezone,
                source="IANA TZDB",
                requires_review=False,
            )
            updates.append(update)
            report.updates_found += 1

    return updates


def apply_updates(data: dict, updates: list[CityUpdate]) -> int:
    """Apply updates to registry data.

    Args:
        data: Registry data.
        updates: Updates to apply.

    Returns:
        Number of updates applied.
    """
    applied = 0
    cities = data.get("cities", [])

    # Create lookup by code
    city_lookup = {c.get("code"): c for c in cities}

    for update in updates:
        if update.requires_review:
            continue

        city = city_lookup.get(update.code)
        if city:
            city[update.field] = update.new_value
            applied += 1

    return applied


def print_report(report: SyncReport, verbose: bool = False) -> None:
    """Print synchronization report.

    Args:
        report: Sync report.
        verbose: Whether to print details.
    """
    print("\n" + "=" * 60)
    print("City Registry Sync Report")
    print("=" * 60)
    print(f"Cities Checked:    {report.cities_checked}")
    print(f"Updates Found:     {report.updates_found}")
    print(f"Updates Applied:   {report.updates_applied}")
    print(f"Reviews Required:  {report.reviews_required}")

    if verbose and report.updates:
        print("\nPending Updates:")
        for update in report.updates:
            status = "[REVIEW]" if update.requires_review else "[AUTO]"
            print(f"  {status} {update.code}.{update.field}: "
                  f"{update.old_value} -> {update.new_value}")


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for registry sync.

    Args:
        argv: Command-line arguments.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path.cwd(),
        help="Repository root path",
    )
    parser.add_argument(
        "--city",
        help="Specific city code to sync",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show changes without applying",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply auto-approved updates",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args(argv)

    # Load registry
    registry_path = args.path / "data" / "cities.json"
    if not registry_path.exists():
        print(f"Error: Registry not found at {registry_path}", file=sys.stderr)
        return 1

    data = load_registry(registry_path)
    cities = data.get("cities", [])

    print("=" * 60)
    print("UCID City Registry Synchronization")
    print("=" * 60)
    print(f"Registry: {registry_path}")
    print(f"Cities: {len(cities)}")

    # Sync cities
    report = SyncReport()

    for city in cities:
        if args.city and city.get("code") != args.city:
            continue

        updates = sync_city(city, report)
        report.updates.extend(updates)

    # Apply updates if requested
    if args.apply and not args.dry_run:
        report.updates_applied = apply_updates(data, report.updates)
        save_registry(registry_path, data)

    # Print report
    print_report(report, verbose=args.verbose)

    if args.dry_run:
        print("\n[DRY RUN] No changes were applied")

    return 0


if __name__ == "__main__":
    sys.exit(main())
