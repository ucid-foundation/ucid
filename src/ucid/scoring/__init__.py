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
"""

from ucid.scoring.grading import grade_to_score_range, score_to_grade
from ucid.scoring.normalization import (
    min_max_normalize,
    normalize_score,
    z_score_normalize,
)

__all__ = [
    "normalize_score",
    "min_max_normalize",
    "z_score_normalize",
    "score_to_grade",
    "grade_to_score_range",
]
