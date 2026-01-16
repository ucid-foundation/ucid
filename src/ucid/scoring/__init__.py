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

"""UCID Scoring module.

This module provides scoring utilities including normalization,
grade assignment, calibration, and uncertainty quantification.

Submodules:
    grading: Score to grade conversion
    normalization: Score normalization functions
    calibration: Isotonic/temperature calibration, ECE/MCE metrics

Example:
    >>> from ucid.scoring import score_to_grade, IsotonicCalibrator
    >>> grade = score_to_grade(0.85)
    >>> print(grade)
    B

Author: UCID Foundation
License: EUPL-1.2
"""

from ucid.scoring.calibration import (
    CalibrationError,
    IsotonicCalibrator,
    TemperatureScaler,
    calibration_curve,
    compute_confidence_interval,
    expected_calibration_error,
    maximum_calibration_error,
)
from ucid.scoring.grading import (
    get_grade_color,
    get_grade_description,
    grade_to_score_range,
    score_to_grade,
)
from ucid.scoring.normalization import (
    min_max_normalize,
    normalize_score,
    z_score_normalize,
)

__all__ = [
    # Normalization
    "normalize_score",
    "min_max_normalize",
    "z_score_normalize",
    # Grading
    "score_to_grade",
    "grade_to_score_range",
    "get_grade_color",
    "get_grade_description",
    # Calibration (new in v1.0.5)
    "IsotonicCalibrator",
    "TemperatureScaler",
    "expected_calibration_error",
    "maximum_calibration_error",
    "compute_confidence_interval",
    "calibration_curve",
    "CalibrationError",
]

