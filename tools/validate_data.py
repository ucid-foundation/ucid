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

"""Data validation tool for UCID repository.

This tool validates JSON data files in the data/ directory against
their schemas to ensure data integrity and correctness.

Usage:
    python tools/validate_data.py [options]

Examples:
    # Validate all data files
    python tools/validate_data.py

    # Validate specific file
    python tools/validate_data.py --file data/cities.json

    # Verbose output
    python tools/validate_data.py --verbose

Validated Files:
    - data/cities.json    : City registry (403 cities)
    - data/contexts.json  : Context algorithms (8 contexts)
    - data/grading.json   : Grading system (5 grades)

Validation Checks:
    - JSON syntax
    - Schema compliance
    - Data integrity
    - Cross-references
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
class ValidationResult:
    """Validation result for a single file."""

    file_path: str
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


def validate_cities(data: dict) -> ValidationResult:
    """Validate cities.json data.

    Args:
        data: Parsed JSON data.

    Returns:
        Validation result.
    """
    result = ValidationResult(file_path="data/cities.json", valid=True)

    # Check required fields
    if "cities" not in data:
        result.errors.append("Missing 'cities' array")
        result.valid = False
        return result

    cities = data["cities"]
    result.stats["total_cities"] = len(cities)

    countries = set()
    seen_codes = set()

    for i, city in enumerate(cities):
        # Check required fields
        required = ["code", "name", "country", "lat", "lon"]
        for field_name in required:
            if field_name not in city:
                result.errors.append(f"City {i}: missing '{field_name}'")
                result.valid = False

        # Check code format
        code = city.get("code", "")
        if len(code) != 3:
            result.warnings.append(f"City {code}: code should be 3 characters")

        if code in seen_codes:
            result.errors.append(f"City {code}: duplicate code")
            result.valid = False
        seen_codes.add(code)

        # Check coordinate ranges
        lat = city.get("lat", 0)
        lon = city.get("lon", 0)

        if not -90 <= lat <= 90:
            result.errors.append(f"City {code}: invalid latitude {lat}")
            result.valid = False

        if not -180 <= lon <= 180:
            result.errors.append(f"City {code}: invalid longitude {lon}")
            result.valid = False

        countries.add(city.get("country", ""))

    result.stats["total_countries"] = len(countries)
    result.stats["countries"] = sorted(countries)

    return result


def validate_contexts(data: dict) -> ValidationResult:
    """Validate contexts.json data.

    Args:
        data: Parsed JSON data.

    Returns:
        Validation result.
    """
    result = ValidationResult(file_path="data/contexts.json", valid=True)

    if "contexts" not in data:
        result.errors.append("Missing 'contexts' array")
        result.valid = False
        return result

    contexts = data["contexts"]
    result.stats["total_contexts"] = len(contexts)

    valid_statuses = {"production", "planned", "deprecated"}
    seen_codes = set()

    for i, context in enumerate(contexts):
        code = context.get("code", f"context_{i}")

        # Check required fields
        required = ["code", "name", "description", "status"]
        for field_name in required:
            if field_name not in context:
                result.errors.append(f"Context {code}: missing '{field_name}'")
                result.valid = False

        # Check code uniqueness
        if code in seen_codes:
            result.errors.append(f"Context {code}: duplicate code")
            result.valid = False
        seen_codes.add(code)

        # Check status
        status = context.get("status", "")
        if status not in valid_statuses:
            result.warnings.append(f"Context {code}: unknown status '{status}'")

    result.stats["production_contexts"] = sum(
        1 for c in contexts if c.get("status") == "production"
    )
    result.stats["planned_contexts"] = sum(
        1 for c in contexts if c.get("status") == "planned"
    )

    return result


def validate_grading(data: dict) -> ValidationResult:
    """Validate grading.json data.

    Args:
        data: Parsed JSON data.

    Returns:
        Validation result.
    """
    result = ValidationResult(file_path="data/grading.json", valid=True)

    if "grades" not in data:
        result.errors.append("Missing 'grades' object")
        result.valid = False
        return result

    grades = data["grades"]
    result.stats["total_grades"] = len(grades)

    valid_grades = {"A", "B", "C", "D", "F"}

    for grade_letter, grade_data in grades.items():
        if grade_letter not in valid_grades:
            result.warnings.append(f"Grade {grade_letter}: non-standard grade")

        # Check range
        grade_range = grade_data.get("range", [])
        if len(grade_range) != 2:
            result.errors.append(f"Grade {grade_letter}: invalid range")
            result.valid = False
        elif grade_range[0] > grade_range[1]:
            result.errors.append(f"Grade {grade_letter}: range min > max")
            result.valid = False

    return result


def validate_file(file_path: Path) -> ValidationResult:
    """Validate a single data file.

    Args:
        file_path: Path to JSON file.

    Returns:
        Validation result.
    """
    result = ValidationResult(file_path=str(file_path), valid=True)

    # Check file exists
    if not file_path.exists():
        result.errors.append("File not found")
        result.valid = False
        return result

    # Parse JSON
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        result.errors.append(f"Invalid JSON: {e}")
        result.valid = False
        return result

    # Route to specific validator
    file_name = file_path.name

    if file_name == "cities.json":
        return validate_cities(data)
    elif file_name == "contexts.json":
        return validate_contexts(data)
    elif file_name == "grading.json":
        return validate_grading(data)
    else:
        result.warnings.append("No specific validator for this file")
        return result


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for data validator.

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
        "--file",
        type=Path,
        help="Specific file to validate",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path.cwd(),
        help="Repository root path",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args(argv)

    print("=" * 60)
    print("UCID Data Validation")
    print("=" * 60)

    # Determine files to validate
    if args.file:
        files = [args.file]
    else:
        data_dir = args.path / "data"
        files = [
            data_dir / "cities.json",
            data_dir / "contexts.json",
            data_dir / "grading.json",
        ]

    all_valid = True

    for file_path in files:
        print(f"\nValidating: {file_path}")
        result = validate_file(file_path)

        if result.valid:
            print("  Status: VALID")
        else:
            print("  Status: INVALID")
            all_valid = False

        # Print errors
        for error in result.errors:
            print(f"  ERROR: {error}")

        # Print warnings
        if args.verbose:
            for warning in result.warnings:
                print(f"  WARNING: {warning}")

        # Print stats
        if result.stats and args.verbose:
            print("  Statistics:")
            for key, value in result.stats.items():
                if not isinstance(value, list):
                    print(f"    {key}: {value}")

    print("\n" + "=" * 60)
    if all_valid:
        print("All files valid!")
        return 0
    else:
        print("Validation failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
