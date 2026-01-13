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

"""Unit tests for scoring module."""

from ucid.scoring import sensitivity


def test_sensitivity() -> None:
    """Test sensitivity analysis on a simple function."""

    def func(x: int) -> int:
        return x * 2

    res = sensitivity.analyze_sensitivity(func, {"x": 1}, {"x": [1, 2, 3]})
    assert res["baseline"] == 2
    assert res["variations"]["x"] == [2, 4, 6]
