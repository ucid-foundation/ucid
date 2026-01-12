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

"""UCID Compute module.

This module provides distributed computing capabilities for UCID,
supporting local, Dask, and Ray backends.
"""

from ucid.compute.base import BaseExecutor
from ucid.compute.local import LocalExecutor

__all__ = [
    "BaseExecutor",
    "LocalExecutor",
]
