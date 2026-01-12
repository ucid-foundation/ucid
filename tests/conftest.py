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

"""Pytest configuration and fixtures for UCID tests."""

import pytest


@pytest.fixture
def sample_ucid_string() -> str:
    """Return a valid sample UCID string for testing."""
    return "UCID-V1:IST:+41.015:+28.979:9:891f2ed6df7ffff:2026W01T12:15MIN:A:0.95:"


@pytest.fixture
def sample_coordinates() -> tuple[float, float]:
    """Return sample coordinates (lat, lon) for testing."""
    return (41.015, 28.979)


@pytest.fixture
def sample_city() -> str:
    """Return a sample city code for testing."""
    return "IST"


@pytest.fixture
def sample_timestamp() -> str:
    """Return a sample timestamp for testing."""
    return "2026W01T12"
