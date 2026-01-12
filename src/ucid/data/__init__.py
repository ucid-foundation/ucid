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

"""UCID Data module.

This module provides data connectors for external data sources
including OpenStreetMap, GTFS transit feeds, and raster data.
"""

from ucid.data.gtfs import GTFSManager
from ucid.data.osm import OSMFetcher

__all__ = [
    "GTFSManager",
    "OSMFetcher",
]
