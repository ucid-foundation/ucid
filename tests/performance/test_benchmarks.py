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

"""Performance benchmarks for UCID operations.

This module contains pytest-benchmark tests to measure the performance
of critical UCID operations including parsing, creation, and validation.

Example:
    Run benchmarks with pytest:
    $ pytest tests/performance/ --benchmark-only
"""

from ucid.core.parser import parse_ucid


def test_parse_benchmark(benchmark) -> None:
    """Benchmark UCID parsing performance.

    Measures the time required to parse a valid UCID string into
    a UCID object. Target: >10,000 operations per second.

    Args:
        benchmark: pytest-benchmark fixture.
    """
    valid_ucid = "UCID-V1:IST:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"

    def _parse() -> None:
        parse_ucid(valid_ucid)

    benchmark(_parse)
