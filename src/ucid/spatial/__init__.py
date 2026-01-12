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

"""UCID Spatial module.

This module provides spatial operations including H3 indexing,
grid generation, and geometric utilities.
"""

from ucid.spatial.grid import generate_grid_h3, scan_city_grid
from ucid.spatial.h3_ops import (
    cell_to_boundary,
    cell_to_latlng,
    get_resolution,
    k_ring,
    latlng_to_cell,
)

__all__ = [
    "get_resolution",
    "k_ring",
    "cell_to_boundary",
    "latlng_to_cell",
    "cell_to_latlng",
    "generate_grid_h3",
    "scan_city_grid",
]
