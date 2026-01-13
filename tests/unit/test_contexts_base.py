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

"""Unit tests for context utilities."""

from ucid.contexts.utils import merge_configs


def test_merge_configs() -> None:
    """Test deep merging of config dictionaries."""
    d1 = {"a": 1, "b": {"c": 2}}
    d2 = {"b": {"d": 3}}
    merged = merge_configs(d1, d2)
    assert merged["a"] == 1
    assert merged["b"]["c"] == 2
    assert merged["b"]["d"] == 3
