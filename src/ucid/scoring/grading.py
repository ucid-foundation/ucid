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
using configurable thresholds. Supports both 0-1 (normalized) and 0-100 scales.

Example:
    >>> from ucid.scoring.grading import score_to_grade
    >>> grade = score_to_grade(0.85)  # 0-1 scale, auto-detected
    >>> print(grade)
    A
    >>> grade = score_to_grade(85)  # 0-100 scale, auto-detected
    >>> print(grade)
    A
"""

from __future__ import annotations

from typing import Literal

# Default grade thresholds (0-100 scale)
DEFAULT_THRESHOLDS: dict[str, float] = {
    "A+": 90.0,
    "A": 80.0,
    "B": 70.0,
    "C": 60.0,
    "D": 50.0,
    "F": 0.0,
}

# Normalized thresholds (0-1 scale)
NORMALIZED_THRESHOLDS: dict[str, float] = {
    "A+": 0.90,
    "A": 0.80,
    "B": 0.70,
    "C": 0.60,
    "D": 0.50,
    "F": 0.0,
}


def score_to_grade(
    score: float,
    thresholds: dict[str, float] | None = None,
    scale: Literal["auto", "0-1", "0-100"] = "auto",
) -> str:
    """Convert a raw score to a letter grade.

    Supports both normalized (0-1) and percentage (0-100) scales.
    By default, automatically detects the scale based on score value.

    Args:
        score: Raw score. If > 1.0, assumed to be 0-100 scale.
               If <= 1.0, assumed to be 0-1 scale (unless scale specified).
        thresholds: Optional custom thresholds. If None, uses default
                   thresholds matching the detected scale.
        scale: Scale mode. "auto" (default) detects from score value,
               "0-1" forces normalized scale, "0-100" forces percentage.

    Returns:
        Letter grade (A+, A, B, C, D, or F).

    Example:
        >>> score_to_grade(0.85)  # Auto-detected as 0-1 scale
        'A'
        >>> score_to_grade(85)  # Auto-detected as 0-100 scale
        'A'
        >>> score_to_grade(0.75, scale="0-1")  # Explicit 0-1 scale
        'B'
    """
    # Determine scale
    if scale == "auto":
        # Scores > 1.0 are assumed to be on 0-100 scale
        use_normalized = score <= 1.0
    elif scale == "0-1":
        use_normalized = True
    else:
        use_normalized = False

    # Select thresholds
    if thresholds is None:
        thresholds = NORMALIZED_THRESHOLDS if use_normalized else DEFAULT_THRESHOLDS

    # Get threshold values
    t_aplus = thresholds.get("A+", 0.90 if use_normalized else 90.0)
    t_a = thresholds.get("A", 0.80 if use_normalized else 80.0)
    t_b = thresholds.get("B", 0.70 if use_normalized else 70.0)
    t_c = thresholds.get("C", 0.60 if use_normalized else 60.0)
    t_d = thresholds.get("D", 0.50 if use_normalized else 50.0)

    if score >= t_aplus:
        return "A+"
    elif score >= t_a:
        return "A"
    elif score >= t_b:
        return "B"
    elif score >= t_c:
        return "C"
    elif score >= t_d:
        return "D"
    else:
        return "F"


def grade_to_score_range(
    grade: str,
    scale: Literal["0-1", "0-100"] = "0-1",
) -> tuple[float, float]:
    """Get the score range for a letter grade.

    Args:
        grade: Letter grade (A+, A, B, C, D, or F).
        scale: Output scale. "0-1" for normalized, "0-100" for percentage.

    Returns:
        Tuple of (min_score, max_score) for the grade.

    Example:
        >>> grade_to_score_range("A")
        (0.8, 0.9)
        >>> grade_to_score_range("A", scale="0-100")
        (80.0, 90.0)
    """
    if scale == "0-1":
        ranges = {
            "A+": (0.90, 1.0),
            "A": (0.80, 0.90),
            "B": (0.70, 0.80),
            "C": (0.60, 0.70),
            "D": (0.50, 0.60),
            "F": (0.0, 0.50),
        }
        default = (0.0, 1.0)
    else:
        ranges = {
            "A+": (90.0, 100.0),
            "A": (80.0, 90.0),
            "B": (70.0, 80.0),
            "C": (60.0, 70.0),
            "D": (50.0, 60.0),
            "F": (0.0, 50.0),
        }
        default = (0.0, 100.0)

    return ranges.get(grade.upper(), default)


def get_grade_color(grade: str) -> str:
    """Get the color code associated with a grade.

    Args:
        grade: Letter grade.

    Returns:
        Hex color code for the grade.

    Example:
        >>> get_grade_color("A")
        '#4CAF50'
    """
    colors = {
        "A+": "#2E7D32",  # Dark green
        "A": "#4CAF50",   # Green
        "B": "#8BC34A",   # Light green
        "C": "#FFC107",   # Amber
        "D": "#FF9800",   # Orange
        "F": "#F44336",   # Red
    }
    return colors.get(grade.upper(), "#9E9E9E")


def get_grade_description(grade: str) -> str:
    """Get a human-readable description for a grade.

    Args:
        grade: Letter grade.

    Returns:
        Description of what the grade means.

    Example:
        >>> get_grade_description("A")
        'Excellent - High quality urban conditions'
    """
    descriptions = {
        "A+": "Outstanding - Exceptional urban conditions",
        "A": "Excellent - High quality urban conditions",
        "B": "Good - Above average urban conditions",
        "C": "Satisfactory - Average urban conditions",
        "D": "Needs Improvement - Below average conditions",
        "F": "Poor - Significant improvements needed",
    }
    return descriptions.get(grade.upper(), "Unknown grade")

