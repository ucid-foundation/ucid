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

"""Unit tests for ML pipeline."""

from ucid.ml.evaluation import calculate_metrics
from ucid.ml.features import FeaturePipeline


def test_metrics() -> None:
    """Test metric calculation with perfect predictions."""
    res = calculate_metrics([1.0], [1.0])
    assert res["mse"] == 0.0


def test_pipeline() -> None:
    """Test feature pipeline fit and transform."""
    fp = FeaturePipeline()
    assert fp.fit([]).transform([]).shape == (1, 1)
