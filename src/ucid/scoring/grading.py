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

"""Grade assignment utilities for UCID.

This module provides functions for converting raw scores to letter grades
using configurable thresholds.
"""

# Default grade thresholds per UCID specification
DEFAULT_THRESHOLDS: dict[str, float] = {
    "A+": 90.0,
    "A": 80.0,
    "B": 70.0,
    "C": 60.0,
    "D": 50.0,
    "F": 0.0,
}


def score_to_grade(
    score: float,
    thresholds: dict[str, float] | None = None,
) -> str:
    """Convert a raw score to a letter grade.

    Args:
        score: Raw score in [0, 100].
        thresholds: Optional custom thresholds.

    Returns:
        Letter grade (A+, A, B, C, D, or F).
    """
    if thresholds is None:
        thresholds = DEFAULT_THRESHOLDS

    if score >= thresholds.get("A+", 90.0):
        return "A+"
    elif score >= thresholds.get("A", 80.0):
        return "A"
    elif score >= thresholds.get("B", 70.0):
        return "B"
    elif score >= thresholds.get("C", 60.0):
        return "C"
    elif score >= thresholds.get("D", 50.0):
        return "D"
    else:
        return "F"


def grade_to_score_range(grade: str) -> tuple[float, float]:
    """Get the score range for a letter grade.

    Args:
        grade: Letter grade.

    Returns:
        Tuple of (min_score, max_score) for the grade.
    """
    ranges = {
        "A+": (90.0, 100.0),
        "A": (80.0, 89.99),
        "B": (70.0, 79.99),
        "C": (60.0, 69.99),
        "D": (50.0, 59.99),
        "F": (0.0, 49.99),
    }
    return ranges.get(grade.upper(), (0.0, 100.0))
