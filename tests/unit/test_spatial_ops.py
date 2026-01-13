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

"""Unit tests for spatial operations."""

from ucid.spatial import aggregation, crs


def test_haversine() -> None:
    """Test haversine distance calculation."""
    dist = crs.CRSops.haversine_distance(0, 0, 0, 1)
    assert 111000 < dist < 112000  # Approx 111km


def test_aggregation() -> None:
    """Test score aggregation."""
    assert aggregation.aggregate_scores([10, 20, 30]) == 20.0
