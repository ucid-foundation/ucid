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

"""Test data fixtures for UCID tests.

This module provides reusable pytest fixtures for testing,
including sample cities, UCIDs, and mock GTFS data.
"""

import shutil

import pytest

from ucid.core.parser import create_ucid


@pytest.fixture
def sample_cities() -> dict[str, dict[str, float]]:
    """Return sample city coordinates for testing.

    Returns:
        Dictionary mapping city codes to lat/lon coordinates.
    """
    return {
        "IST": {"lat": 41.0082, "lon": 28.9784},
        "NYC": {"lat": 40.7128, "lon": -74.0060},
        "LON": {"lat": 51.5074, "lon": -0.1278},
    }


@pytest.fixture
def sample_ucids(sample_cities: dict[str, dict[str, float]]) -> list[str]:
    """Generate sample UCID strings for testing.

    Args:
        sample_cities: Dictionary of city coordinates.

    Returns:
        List of UCID strings for each city.
    """
    ucids = []
    for code, coords in sample_cities.items():
        u = create_ucid(
            city=code,
            lat=coords["lat"],
            lon=coords["lon"],
            timestamp="2026W01T12",
            context="TEST",
            grade="A",
        )
        ucids.append(str(u))
    return ucids


@pytest.fixture
def mock_gtfs_path(tmp_path):
    """Create a mock GTFS zip file for testing.

    Args:
        tmp_path: pytest's temporary directory fixture.

    Returns:
        Path to the created GTFS zip file.
    """
    d = tmp_path / "gtfs"
    d.mkdir()
    (d / "agency.txt").write_text("agency_id,agency_name\n1,Demo Transit")
    (d / "stops.txt").write_text("stop_id,stop_name,stop_lat,stop_lon\n1,Stop A,40.0,20.0")

    zip_path = tmp_path / "test.zip"
    shutil.make_archive(str(zip_path.with_suffix("")), "zip", d)
    return zip_path
