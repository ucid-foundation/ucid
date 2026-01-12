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

"""CSV file operations for UCID data.

This module provides functions for reading and writing UCID data
in CSV format.
"""

import csv
from pathlib import Path
from typing import Any


def write_csv(data: list[dict[str, Any]], path: str | Path) -> None:
    """Write a list of dictionaries to a CSV file.

    Args:
        data: List of dictionaries to write. All dictionaries should
            have the same keys.
        path: Path to the output CSV file.

    Raises:
        ValueError: If data is empty and headers cannot be determined.

    Example:
        >>> data = [{"city": "IST", "score": 85.0}]
        >>> write_csv(data, "output.csv")
    """
    if not data:
        return

    keys = list(data[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)


def read_csv(path: str | Path) -> list[dict[str, Any]]:
    """Read a CSV file into a list of dictionaries.

    Args:
        path: Path to the CSV file.

    Returns:
        List of dictionaries, one per row.

    Example:
        >>> data = read_csv("input.csv")
        >>> print(data[0]["city"])
    """
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)
